/*****************************************************************************\
**                                                                           **
** PBX4Linux                                                                 **
**                                                                           **
**---------------------------------------------------------------------------**
** Copyright: Andreas Eversberg                                              **
**                                                                           **
** Administration tool                                                       **
**                                                                           **
\*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <curses.h>
#include "save.h"
#include "call.h"
#include "callpbx.h"
#include "admin.h"
#include "cause.h"

#define LTEE {addch(ACS_LTEE);addch(ACS_HLINE);addch(ACS_HLINE);}
#define LLCORNER {addch(ACS_LLCORNER);addch(ACS_HLINE);addch(ACS_HLINE);}
#define VLINE {addch(ACS_VLINE);addstr("  ");}
#define EMPTY {addstr("   ");}
//char rotator[] = {'-', '\\', '|', '/'};
int	lastlines, lastcols;
int	show_interfaces = 2,
	show_calls = 1,
	show_log = 1;

enum {
	MODE_STATE,
	MODE_INTERFACE,
	MODE_ROUTE,
	MODE_DIAL,
	MODE_RELEASE,
	MODE_TESTCALL,
	MODE_TRACE,
};

char *text_interfaces[] = {
	"off",
	"brief",
	"active channels",
	"all channels",
};

char *text_calls[] = {
	"off",
	"brief",
	"structured",
};

char	red = 1,
	green = 2,
	yellow = 3,
	blue = 4,
	mangenta = 5,
	cyan = 6,
	white = 7;

#define LOGLINES 128
char logline[LOGLINES][256];
unsigned long logcur = 0;
int logfh = -1;
char logfile[128];

/*
 * curses
 */
void init_curses(void)
{
	/* init curses */
        initscr(); cbreak(); noecho();
        start_color();
        nodelay(stdscr, TRUE);
        if (COLOR_PAIRS>=8 && COLORS>=8)
        {
                init_pair(1,1,0);
                init_pair(2,2,0);
                init_pair(3,3,0);
                init_pair(4,4,0);
                init_pair(5,5,0);
                init_pair(6,6,0);
                init_pair(7,7,0);
        }
	lastlines = LINES;
	lastcols = COLS;
}

void cleanup_curses(void)
{
        endwin();
}

void color(int color)
{
        if (COLOR_PAIRS>=8 && COLORS>=8)
		attrset(COLOR_PAIR(color));
}

/*
 * permanently show current state using ncurses
 */
int debug_port(struct admin_message *msg, struct admin_message *m, int line, int i, int vline)
{
	char buffer[256];

	color(white);
	addstr("PORT:");
	color(yellow);
	SPRINT(buffer,"%s(%d)", m[i].u.p.name,m[i].u.p.serial);
	addstr(buffer);
	color(cyan);
	addstr(" state=");
	switch (m[i].u.p.state)
	{
		case ADMIN_STATE_IDLE:
		color(red);
		addstr("'idle'");
		break;
		case ADMIN_STATE_IN_SETUP:
		color(red);
		addstr("'in << setup'");
		break;
		case ADMIN_STATE_OUT_SETUP:
		color(red);
		addstr("'out >> setup'");
		break;
		case ADMIN_STATE_IN_OVERLAP:
		color(yellow);
		addstr("'in << overlap'");
		break;
		case ADMIN_STATE_OUT_OVERLAP:
		color(yellow);
		addstr("'out >> overlap'");
		break;
		case ADMIN_STATE_IN_PROCEEDING:
		color(mangenta);
		addstr("'in << proc'");
		break;
		case ADMIN_STATE_OUT_PROCEEDING:
		color(mangenta);
		addstr("'out >> proc'");
		break;
		case ADMIN_STATE_IN_ALERTING:
		color(cyan);
		addstr("'in << alert'");
		break;
		case ADMIN_STATE_OUT_ALERTING:
		color(cyan);
		addstr("'out >> alert'");
		break;
		case ADMIN_STATE_CONNECT:
		color(white);
		addstr("'connect'");
		break;
		case ADMIN_STATE_IN_DISCONNECT:
		color(blue);
		addstr("'in  << disc'");
		break;
		case ADMIN_STATE_OUT_DISCONNECT:
		color(blue);
		addstr("'out >> disc'");
		break;
		default:
		color(blue);
		addstr("'--NONE--'");
	}

	if (m[i].u.p.isdn)
	{	
		color(cyan);
		addstr(" bchannel=");
		color(white);
		SPRINT(buffer,"%d", m[i].u.p.isdn_chan);
		addstr(buffer);
		if (m[i].u.p.isdn_ces >= 0)
		{
			color(cyan);
			addstr(" ces=");
			color(yellow);
			SPRINT(buffer, "%d", m[i].u.p.isdn_ces);
			addstr(buffer);
		}
		if (m[i].u.p.isdn_hold)
		{
			color(red);
			addstr(" hold");
		}
	}

	return(line);
}
int debug_epoint(struct admin_message *msg, struct admin_message *m, int line, int i, int vline)
{
	unsigned long epoint = m[i].u.e.serial;
	char buffer[256];
	unsigned char c;
	int j, jj;
	int ltee;

	color(white);
	SPRINT(buffer,"EPOINT(%d)", epoint);
	addstr(buffer);
	color(cyan);
	addstr(" state=");
	switch (m[i].u.e.state)
	{
		case ADMIN_STATE_IDLE:
		color(red);
		addstr("'idle'");
		break;
		case ADMIN_STATE_IN_SETUP:
		color(red);
		addstr("'in << setup'");
		break;
		case ADMIN_STATE_OUT_SETUP:
		color(red);
		addstr("'out >> setup'");
		break;
		case ADMIN_STATE_IN_OVERLAP:
		color(yellow);
		addstr("'in << overlap'");
		break;
		case ADMIN_STATE_OUT_OVERLAP:
		color(yellow);
		addstr("'out >> overlap'");
		break;
		case ADMIN_STATE_IN_PROCEEDING:
		color(mangenta);
		addstr("'in << proc'");
		break;
		case ADMIN_STATE_OUT_PROCEEDING:
		color(mangenta);
		addstr("'out >> proc'");
		break;
		case ADMIN_STATE_IN_ALERTING:
		color(cyan);
		addstr("'in << alert'");
		break;
		case ADMIN_STATE_OUT_ALERTING:
		color(cyan);
		addstr("'out >> alert'");
		break;
		case ADMIN_STATE_CONNECT:
		color(white);
		addstr("'connect'");
		break;
		case ADMIN_STATE_IN_DISCONNECT:
		color(blue);
		addstr("'in  << disc'");
		break;
		case ADMIN_STATE_OUT_DISCONNECT:
		color(blue);
		addstr("'out >> disc'");
		break;
		default:
		color(blue);
		addstr("'--NONE--'");
	}
	if (m[i].u.e.terminal[0])
	{
		color(cyan);
		addstr(" terminal=");
		color(green);
		addstr(m[i].u.e.terminal);
	}
	color(white);
	SPRINT(buffer, " %s", m[i].u.e.callerid);
	addstr(buffer);
	color(cyan);
	addstr("->");
	color(white);
	addstr(m[i].u.e.dialing);
	if (m[i].u.e.action[0])
	{
		color(cyan);
		addstr(" action=");
		color(yellow);
		addstr(m[i].u.e.action);
	}
	if (m[i].u.e.park)
	{
		color(cyan);
		addstr(" park="); /* 9 digits */
		color(green);
		UCPY(buffer, "\""); /* 9 digits */
		j = 0;
		jj = m[i].u.e.park_len;
		while(j < jj)
		{
			c = m[i].u.e.park_callid[j];
			if (c >= 32 && c < 127 && c != '[')
			{
				SCCAT(buffer, c);
			} else
				UPRINT(buffer+strlen(buffer), "[%02x]", c);
			j++;
		}
		SCAT(buffer, "\"");
		addstr(buffer);
	} else
	{
		color(red);
		switch(m[i].u.e.rx_state)
		{
			case NOTIFY_STATE_SUSPEND:
			addstr(" in=suspend");
			break;
			case NOTIFY_STATE_HOLD:
			addstr(" in=hold");
			break;
			case NOTIFY_STATE_CONFERENCE:
			addstr(" in=conference");
			break;
		}
		switch(m[i].u.e.tx_state)
		{
			case NOTIFY_STATE_SUSPEND:
			addstr(" out=suspend");
			break;
			case NOTIFY_STATE_HOLD:
			addstr(" out=hold");
			break;
			case NOTIFY_STATE_CONFERENCE:
			addstr(" out=conference");
			break;
		}
	}
	if (m[i].u.e.crypt)
	{
		color(cyan);
		addstr(" crypt=");
		if (m[i].u.e.crypt) /* crypt on */
		{
			color(green);
			addstr("active");
		} else
		{
			color(yellow);
			addstr("pending");
		}
	}
	/* loop all related ports */
	ltee = 0;
	j = msg->u.s.interfaces+msg->u.s.calls+msg->u.s.epoints;
	jj = j + msg->u.s.ports;
	while(j < jj)
	{
		if (m[j].u.p.epoint == epoint)
		{
			color(cyan);
			move(++line>1?line:1, 1);
			if (vline)
				VLINE
			else
				EMPTY
			move(line>1?line:1, 5);
			LTEE
			ltee = line;
			move(line>1?line:1, 8);
			if (line+2 >= LINES) break;
			line = debug_port(msg, m, line, j, vline);
			if (line+2 >= LINES) break;
		}
		j++;
	}
	if (ltee)
	{
		color(cyan);
		move(ltee>1?line:1, 5);
		LLCORNER
	}

	return(line);
}
int debug_call(struct admin_message *msg, struct admin_message *m, int line, int i)
{
	unsigned long	call = m[i].u.c.serial;
	char		buffer[256];
	int		j, jj;

	color(white);
	SPRINT(buffer,"CALL(%d)", call);
	addstr(buffer);
	if (m[i].u.c.partyline)
	{
		color(cyan);
		addstr(" partyline=");
		color(white);
		SPRINT(buffer, "%d\n", m[i].u.c.partyline);
		addstr(buffer);
	}
	/* find number of epoints */
	j = msg->u.s.interfaces+msg->u.s.calls;
	jj = j + msg->u.s.epoints;
	i = 0;
	while(j < jj)
	{
		if (m[j].u.e.call == call)
			i++;
		j++;
	}
	/* loop all related endpoints */
	j = msg->u.s.interfaces+msg->u.s.calls;
	jj = j + msg->u.s.epoints;
	while(j < jj)
	{
		if (m[j].u.e.call == call)
		{
			i--;
			move(++line>1?line:1, 1);
			color(cyan);
			if (i)
				LTEE
			else
				LLCORNER
			move(line>1?line:1, 4);
			if (line+2 >= LINES) break;
			line = debug_epoint(msg, m, line, j, i?1:0);
			if (line+2 >= LINES) break;
		}
		j++;
	}

	return(line);
}
char *admin_state(int sock)
{
	struct admin_message	msg,
				*m;
	char			buffer[256],
				*p;
	int			line, offset = 0;
	int			i, ii, j, jj, k;
	unsigned long		l, ll;
	int			num;
	int			len;
	int			off;
	int			ltee;
	int			anything;

	/* flush logfile name */
	logfile[0] = '\0';

	/* init curses */
	init_curses();

	again:
	/* send reload command */
	memset(&msg, 0, sizeof(msg));
	msg.message = ADMIN_REQUEST_STATE;
//	printf("sizeof=%d\n",sizeof(msg));
	if (write(sock, &msg, sizeof(msg)) != sizeof(msg))
	{
		cleanup_curses();
		return("Broken pipe while sending command.");
	}

	/* receive response */
	if (read(sock, &msg, sizeof(msg)) != sizeof(msg))
	{
		cleanup_curses();
		return("Broken pipe while receiving response.");
	}
	if (msg.message != ADMIN_RESPONSE_STATE)
	{
		cleanup_curses();
		return("Response not valid. Expecting state response.");
	}
	num = msg.u.s.interfaces + msg.u.s.calls + msg.u.s.epoints + msg.u.s.ports;
	if (!(m = (struct admin_message *)malloc(num*sizeof(struct admin_message))))
	{
		cleanup_curses();
		return("Not enough memory for messages.");
	}
	off=0;
readagain:
	if ((len = read(sock, ((unsigned char *)(m))+off,
				       	num*sizeof(struct admin_message)-off)) != num*sizeof(struct admin_message)-off)
	{
		if (len <= 0) {
			free(m);
//			fprintf(stderr, "got=%d expected=%d\n", i, num*sizeof(struct admin_message));
			cleanup_curses();
			return("Broken pipe while receiving state infos.");
		}
		if (len < num*sizeof(struct admin_message))
		{
			off+=len;
			goto readagain;
		}
	}
	j = 0;
	i = 0;
//	fprintf("getting =%d interfaces\n", msg.u.s.interfaces);
	while(i < msg.u.s.interfaces)
	{
//		fprintf(stderr, "j=%d message=%d\n", j, m[j].message);
		if (m[j].message != ADMIN_RESPONSE_S_INTERFACE)
		{
			free(m);
			cleanup_curses();
			return("Response not valid. Expecting interface information.");
		}
		i++;
		j++;
	}
	i = 0;
	while(i < msg.u.s.calls)
	{
		if (m[j].message != ADMIN_RESPONSE_S_CALL)
		{
			free(m);
			cleanup_curses();
			return("Response not valid. Expecting call information.");
		}
		i++;
		j++;
	}
	i = 0;
	while(i < msg.u.s.epoints)
	{
		if (m[j].message != ADMIN_RESPONSE_S_EPOINT)
		{
			free(m);
			cleanup_curses();
			return("Response not valid. Expecting endpoint information.");
		}
		i++;
		j++;
	}
	i = 0;
	while(i < msg.u.s.ports)
	{
		if (m[j].message != ADMIN_RESPONSE_S_PORT)
		{
			free(m);
			cleanup_curses();
			return("Response not valid. Expecting port information.");
		}
		i++;
		j++;
	}
	// now j is the number of message blocks

	/* display start */
	erase();

	line = 1-offset; 

	/* change log */
	if (!!strcmp(logfile, msg.u.s.logfile))
	{
		SCPY(logfile, msg.u.s.logfile);
		if (logfh >= 0)
			close(logfh);
		i = 0;
		ii = LOGLINES;
		while(i < ii)
		{
			logline[i][0] = '~';
			logline[i][1] = '\0';
			i++;
		}
		logcur = 0;
		logfh = open(logfile, O_RDONLY|O_NONBLOCK);
		if (logfh >= 0)
		{
			/* seek at the end -8000 chars */
			lseek(logfh, -8000, SEEK_END);
			/* if not at the beginning, read until endofline */
			logline[logcur % LOGLINES][0] = '\0';
			l = read(logfh, logline[logcur % LOGLINES], sizeof(logline[logcur % LOGLINES])-1);
			if (l > 0)
			{
				/* read first line and skip junk */
				logline[logcur % LOGLINES][l] = '\0';
				if ((p = strchr(logline[logcur % LOGLINES],'\n')))
				{
					logcur++;
					SCPY(logline[logcur % LOGLINES], p+1);
					SCPY(logline[(logcur-1) % LOGLINES], "...");
				}
				goto finish_line;
			}
		}
	}

	/* read log */
	if (logfh >= 0)
	{
		while(42)
		{
			ll = strlen(logline[logcur % LOGLINES]);
			l = read(logfh, logline[logcur % LOGLINES]+ll, sizeof(logline[logcur % LOGLINES])-ll-1);
			if (l<=0)
				break;
			logline[logcur % LOGLINES][ll+l] = '\0';
			finish_line:
			/* put data to lines */
			while ((p = strchr(logline[logcur % LOGLINES],'\n')))
			{
				*p = '\0';
				logcur++;
				SCPY(logline[logcur % LOGLINES], p+1);
			}
			/* if line is full without return, go next line */
			if (strlen(logline[logcur % LOGLINES]) == sizeof(logline[logcur % LOGLINES])-1)
			{
				logcur++;
				logline[logcur % LOGLINES][0] = '\0';
			}
		}
	}

	/* display interfaces */
	if (show_interfaces > 0)
	{
		anything = 0;
		i = 0;
		ii = i + msg.u.s.interfaces;
		while(i < ii)
		{
			/* show interface summary */
			move(++line>1?line:1, 0);
			color(white);

			SPRINT(buffer, "%s(%d) '%s' %s use:%d ", (m[i].u.i.ntmode)?"NT":"TE", m[i].u.i.portnum, m[i].u.i.interface_name, (m[i].u.i.ptp)?"ptp ":"ptmp", m[i].u.i.use);
			addstr(buffer);
			if (m[i].u.i.ptp || !m[i].u.i.ntmode)
			{
				color((m[i].u.i.l2link)?green:red);
				addstr((m[i].u.i.l2link)?"  L2 UP":"  L2 down");
			}
			color((m[i].u.i.l1link)?green:blue);
			addstr((m[i].u.i.l1link)?"  L1 ACTIVE":"  L1 inactive");
			if (line+2 >= LINES) goto end;
			/* show channels */
			if (show_interfaces > 1)
			{
				ltee = 0;
				j = k =0;
				jj = m[i].u.i.channels;
				while(j < jj)
				{
					/* show all channels */
					if (show_interfaces>2 || m[i].u.i.busy[j]>0)
					{
						color(cyan);
						/* show left side / right side */
						if ((k & 1) && (COLS > 70))
						{
							move(line>1?line:1,4+((COLS-4)/2));
						} else
						{
							move(++line>1?line:1, 1);
							LTEE
							ltee = 1;
						}
						k++;
						color(white);
						if (m[i].u.i.pri)
							SPRINT(buffer,"S%2d: ", j+1+(j>=15));
						else
							SPRINT(buffer,"B%2d: ", j+1);
						addstr(buffer);
						if (!m[i].u.i.ptp)
							goto ptmp;
						if (m[i].u.i.l2link)
						{
							ptmp:
							color((m[i].u.i.busy[j])?yellow:blue);
							addstr((m[i].u.i.busy[j])?"busy":"idle");
						} else
						{
							color(red);
							addstr("blk ");
						}
						if (m[i].u.i.port[j])
						{
							/* search for port */
							l = msg.u.s.interfaces+msg.u.s.calls+msg.u.s.epoints;
							ll = l+msg.u.s.ports;
							while(l < ll)
							{
								if (m[l].u.p.serial == m[i].u.i.port[j])
								{
									SPRINT(buffer, " %s(%ld)", m[l].u.p.name, m[l].u.p.serial);
									addstr(buffer);
								}
								l++;
							}
						}
						if (line+2 >= LINES)
						{
							if (ltee)
							{
								color(cyan);
								move(line>1?line:1, 1);
								LLCORNER
							}
							goto end;
						}
					}
					j++;
				}
				if (ltee)
				{
					color(cyan);
					move(line>1?line:1, 1);
					LLCORNER
				}
				if (line+2 >= LINES) goto end;
				/* show summary if no channels were shown */
				if (show_interfaces<2 && ltee==0)
				{
					color(cyan);
					move(++line>1?line:1, 1);
					LLCORNER
						
					if (m[i].u.i.l2link)
					{
						color(green);
						SPRINT(buffer,"all %d channels free", m[i].u.i.channels);
					} else
					{
						color(red);
						SPRINT(buffer,"all %d channels blocked", m[i].u.i.channels);
					}
					addstr(buffer);
				}
				if (line+2 >= LINES) goto end;
			}
			i++;
			anything = 1;
		}
		if (anything)
			line++;
		if (line+2 >= LINES) goto end;
	}		
	/* display calls (brief) */
	if (show_calls == 1)
	{
		anything = 0;
		i = msg.u.s.interfaces+msg.u.s.calls;
		ii = i+msg.u.s.epoints;
		while(i < ii)
		{
			/* for each endpoint... */
			if (!m[i].u.e.call)
			{
				move(++line>1?line:1, 0);
				color(white);
				SPRINT(buffer, "(%d): ", m[i].u.e.serial);
				addstr(buffer);
				color(cyan);
				if (m[i].u.e.terminal[0])
				{
					addstr("intern=");
					color(green);
					addstr(m[i].u.e.terminal);
				} else
					addstr("extern");
				color(white);
				SPRINT(buffer, " %s", m[i].u.e.callerid);
				addstr(buffer);
				color(cyan);
				addstr("->");
				color(white);
				SPRINT(buffer, "%s", m[i].u.e.dialing);
				addstr(buffer);
				if (m[i].u.e.action[0])
				{
					color(cyan);
					addstr(" action=");
					color(yellow);
					addstr(m[i].u.e.action);
				}
				if (line+2 >= LINES) goto end;
			}
			i++;
			anything = 1;
		}
		j = msg.u.s.interfaces;
		jj = j+msg.u.s.calls;
		while(j < jj)
		{
			/* for each call... */
			move(++line>1?line:1, 0);
			color(white);
			SPRINT(buffer, "(%d):", m[j].u.c.serial);
			addstr(buffer);
			i = msg.u.s.interfaces+msg.u.s.calls;
			ii = i+msg.u.s.epoints;
			while(i < ii)
			{
				/* for each endpoint... */
				if (m[i].u.e.call == m[j].u.c.serial)
				{
					color(white);
					SPRINT(buffer, " (%d)", m[i].u.e.serial);
					addstr(buffer);
					color(cyan);
					if (m[i].u.e.terminal[0])
					{
						addstr("int=");
						color(green);
						addstr(m[i].u.e.terminal);
					} else
						addstr("ext");
					color(white);
					SPRINT(buffer, "-%s", m[i].u.e.callerid);
					addstr(buffer);
					color(cyan);
					addstr(">");
					color(white);
					SPRINT(buffer, "%s", m[i].u.e.dialing);
					addstr(buffer);
				}
				i++;
				anything = 1;
			}
			if (line+2 >= LINES) goto end;
			j++;
		}
		if (anything)
			line++;
		if (line+2 >= LINES) goto end;
	}
	/* display calls (structurd) */
	if (show_calls == 2)
	{
		/* show all ports with no epoint */
		anything = 0;
		i = msg.u.s.interfaces+msg.u.s.calls+msg.u.s.epoints;
		ii = i+msg.u.s.ports;
		while(i < ii)
		{
			if (!m[i].u.p.epoint)
			{
				move(++line>1?line:1, 8);
				if (line+2 >= LINES) goto end;
				line = debug_port(&msg, m, line, i, 0);
				if (line+2 >= LINES) goto end;
				anything = 1;
			}
			i++;
		}
		if (anything)
			line++;
		if (line+2 >= LINES) goto end;

		/* show all epoints with no call */
		anything = 0;
		i = msg.u.s.interfaces+msg.u.s.calls;
		ii = i+msg.u.s.epoints;
		while(i < ii)
		{
			if (!m[i].u.e.call)
			{
				move(++line>1?line:1, 4);
				if (line+2 >= LINES) goto end;
				line = debug_epoint(&msg, m, line, i, 0);
				if (line+2 >= LINES) goto end;
				anything = 1;
			}
			i++;
		}
		if (anything)
			line++;
		if (line+2 >= LINES) goto end;

		/* show all calls */
		anything = 0;
		i = msg.u.s.interfaces;
		ii = i+msg.u.s.calls;
		while(i < ii)
		{
			move(++line>1?line:1, 0);
			if (line+2 >= LINES) goto end;
			line = debug_call(&msg, m, line, i);
			if (line+2 >= LINES) goto end;
			i++;
			anything = 1;
		}
		if (anything)
			line++;
		if (line+2 >= LINES) goto end;

	}

	/* show log */
	if (show_log)
	{
		if (line+2 < LINES)
		{
			move(line++>1?line-1:1, 0);
			color(blue);
			hline(ACS_HLINE, COLS);
			color(white);
			
			l = logcur-(LINES-line-2);
			ll = logcur;
			if (ll-l >= LOGLINES)
				l = ll-LOGLINES+1;
			while(l!=ll)
			{
				move(line++>1?line-1:1, 0);
				SCPY(buffer, logline[l % LOGLINES]);
				if (COLS < (int)sizeof(buffer))
					buffer[COLS] = '\0';
				addstr(buffer);
				l++;
			}
		}
	}

	end:
	/* free memory */
	free(m);
	/* display name/time */
//	move(0, 0);
//	hline(' ', COLS);
	move(0, 0);
	color(white);
	msg.u.s.version_string[sizeof(msg.u.s.version_string)-1] = '\0';
	SPRINT(buffer, "PBX4Linux %s", msg.u.s.version_string);
	addstr(buffer);
	if (COLS>50)
	{
		move(0, COLS-19);
		SPRINT(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
			msg.u.s.tm.tm_year+1900, msg.u.s.tm.tm_mon+1, msg.u.s.tm.tm_mday,
			msg.u.s.tm.tm_hour, msg.u.s.tm.tm_min, msg.u.s.tm.tm_sec);
		addstr(buffer);
	}
	/* displeay head line */
	move(1, 0);
	color(blue);
	hline(ACS_HLINE, COLS);
	if (offset)
	{
		move(1, 1);
		SPRINT(buffer, "Offset +%d", offset);
		color(red);
		addstr(buffer);
	}
	/* display end */
	move(LINES-2, 0);
	color(white);
	hline(ACS_HLINE, COLS);
	move(LINES-1, 0);
	color(white);
	SPRINT(buffer, "i = interfaces '%s'  c = calls '%s'  l = log  q = quit  +/- = scroll", text_interfaces[show_interfaces], text_calls[show_calls]);
	addstr(buffer);
	refresh();

	/* resize */
	if (lastlines!=LINES || lastcols!=COLS)
	{
		cleanup_curses();
		init_curses();
		goto again;
	}

	/* user input */
	switch(getch())
	{
		case 12: /* refresh */
		cleanup_curses();
		init_curses();
		goto again;
		break;

		case 3: /* abort */
		case 'q':
		case 'Q':
		break;

		case 'i': /* toggle interface */
		show_interfaces++;
		if (show_interfaces > 3) show_interfaces = 0;
		goto again;

		case 'c': /* toggle calls */
		show_calls++;
		if (show_calls > 2) show_calls = 0;
		goto again;

		case 'l': /* toggle log */
		show_log++;
		if (show_log > 1) show_log = 0;
		goto again;

		case '+': /* scroll down */
		offset++;
		goto again;
		
		case '-': /* scroll up */
		if (offset)
			offset--;
		goto again;

		default:
		usleep(250000);
		goto again;
	}

	/* check for logfh */
	if (logfh >= 0)
		close(logfh);
	logfh = -1;

	/* cleanup curses and exit */
	cleanup_curses();

	return(NULL);
}


/*
 * Send command and show error message.
 */
char *admin_cmd(int sock, int mode, char *extension, char *number)
{
	static struct admin_message msg;

	/* send reload command */
	memset(&msg, 0, sizeof(msg));
	switch(mode)
	{
		case MODE_INTERFACE:
		msg.message = ADMIN_REQUEST_CMD_INTERFACE;
		break;
		case MODE_ROUTE:
		msg.message = ADMIN_REQUEST_CMD_ROUTE;
		break;
		case MODE_DIAL:
		msg.message = ADMIN_REQUEST_CMD_DIAL;
		SPRINT(msg.u.x.message, "%s:%s", extension?:"", number?:"");
		break;
		case MODE_RELEASE:
		msg.message = ADMIN_REQUEST_CMD_RELEASE;
		SCPY(msg.u.x.message, number);
		break;
	}

	if (write(sock, &msg, sizeof(msg)) != sizeof(msg))
		return("Broken pipe while sending command.");

	/* receive response */
	if (read(sock, &msg, sizeof(msg)) != sizeof(msg))
		return("Broken pipe while receiving response.");
	switch(mode)
	{
		case MODE_INTERFACE:
		if (msg.message != ADMIN_RESPONSE_CMD_INTERFACE)
			return("Response not valid.");
		break;
		case MODE_ROUTE:
		if (msg.message != ADMIN_RESPONSE_CMD_ROUTE)
			return("Response not valid.");
		break;
		case MODE_DIAL:
		if (msg.message != ADMIN_RESPONSE_CMD_DIAL)
			return("Response not valid.");
		break;
		case MODE_RELEASE:
		if (msg.message != ADMIN_RESPONSE_CMD_RELEASE)
			return("Response not valid.");
		break;
	}

	/* process response */
	if (msg.u.x.error)
	{
		return(msg.u.x.message);
	}
	printf("Command successfull.\n");
	return(NULL);
}


/*
 * makes a testcall
 */
char *admin_testcall(int sock, int argc, char *argv[])
{
	static struct admin_message msg;

	printf("pid=%d\n", getpid()); fflush(stdout);

	/* send reload command */
	memset(&msg, 0, sizeof(msg));
	msg.message = ADMIN_CALL_SETUP;
	if (argc > 2)
	{
		SCPY(msg.u.call.interface, argv[2]);
	}
	if (argc > 3)
	{
		SCPY(msg.u.call.callerid, argv[3]);
	}
	if (argc > 4)
	{
		SCPY(msg.u.call.dialing, argv[4]);
	}
	if (argc > 5)
	{
		if (argv[5][0] == 'p')
			msg.u.call.present = 1;
	}
	msg.u.call.bc_capa = 0x00; /*INFO_BC_SPEECH*/
	msg.u.call.bc_mode = 0x00; /*INFO_BMODE_CIRCUIT*/
	msg.u.call.bc_info1 = 0;
	msg.u.call.hlc = 0;
	msg.u.call.exthlc = 0;
	if (argc > 6)
		msg.u.call.bc_capa = strtol(argv[6],NULL,0);
	else
		msg.u.call.bc_info1 = 3 | 0x80; /* alaw, if no capability is given at all */
	if (argc > 7) {
		msg.u.call.bc_mode = strtol(argv[7],NULL,0);
		if (msg.u.call.bc_mode) msg.u.call.bc_mode = 2;
	}
	if (argc > 8) {
		msg.u.call.bc_info1 = strtol(argv[8],NULL,0);
		if (msg.u.call.bc_info1 < 0)
			msg.u.call.bc_info1 = 0;
		else
			msg.u.call.bc_info1 |= 0x80;
	}
	if (argc > 9) {
		msg.u.call.hlc = strtol(argv[9],NULL,0);
		if (msg.u.call.hlc < 0)
			msg.u.call.hlc = 0;
		else
			msg.u.call.hlc |= 0x80;
	}
//		printf("hlc=%d\n",  msg.u.call.hlc);
	if (argc > 10) {
		msg.u.call.exthlc = strtol(argv[10],NULL,0);
		if (msg.u.call.exthlc < 0)
			msg.u.call.exthlc = 0;
		else
			msg.u.call.exthlc |= 0x80;
	}

	if (write(sock, &msg, sizeof(msg)) != sizeof(msg))
		return("Broken pipe while sending command.");

	/* receive response */
next:
	if (read(sock, &msg, sizeof(msg)) != sizeof(msg))
		return("Broken pipe while receiving response.");
	switch(msg.message)
	{
		case ADMIN_CALL_SETUP_ACK:
		printf("SETUP ACKNOWLEDGE\n"); fflush(stdout);
		goto next;

		case ADMIN_CALL_PROCEEDING:
		printf("PROCEEDING\n"); fflush(stdout);
		goto next;

		case ADMIN_CALL_ALERTING:
		printf("ALERTING\n"); fflush(stdout);
		goto next;

		case ADMIN_CALL_CONNECT:
		printf("CONNECT\n number=%s\n", msg.u.call.callerid); fflush(stdout);
		goto next;

		case ADMIN_CALL_NOTIFY:
		printf("NOTIFY\n notify=%d\n number=%s\n", msg.u.call.notify, msg.u.call.callerid); fflush(stdout);
		goto next;

		case ADMIN_CALL_DISCONNECT:
		printf("DISCONNECT\n cause=%d %s\n location=%d %s\n", msg.u.call.cause, (msg.u.call.cause>0 && msg.u.call.cause<128)?isdn_cause[msg.u.call.cause].german:"", msg.u.call.location, (msg.u.call.location>=0 && msg.u.call.location<128)?isdn_location[msg.u.call.location].german:""); fflush(stdout);
		goto next;

		case ADMIN_CALL_RELEASE:
		printf("RELEASE\n cause=%d %s\n location=%d %s\n", msg.u.call.cause, (msg.u.call.cause>0 && msg.u.call.cause<128)?isdn_cause[msg.u.call.cause].german:"", msg.u.call.location, (msg.u.call.location>=0 && msg.u.call.location<128)?isdn_location[msg.u.call.location].german:""); fflush(stdout);
		break;

		default:
		return("Response not valid.");
	}
	
	printf("Command successfull.\n");
	return(NULL);
}


/*
 * makes a trace
 */
char *admin_trace(int sock, int argc, char *argv[])
{
	static struct admin_message msg;

	/* show help */
	if (!strcasecmp(argv[2], "help"))
	{
		printf("Trace Help\n----------\n");
		printf("%s trace [brief|short] [<filter>=<value> [...]]\n\n", argv[0]);
		printf("By default a complete trace is shown in detailed format.\n");
		printf("To show a more compact format, use 'brief' or 'short' keyword.\n");
		printf("Use filter values to select specific trace messages.\n");
		printf("All given filter values must match. If no filter is given, anything matches.\n\n");
		printf("Filters:\n");
		printf(" category=<mask bits>\n");
		printf("  0x01 = L1: layer 1 trace (application view)\n");
		printf("  0x02 = L2: layer 2 trace (application view)\n");
		printf("  0x04 = L3: layer 3 trace (application view)\n");
		printf("  0x08 = CH: channel selection trace\n");
		printf("  0x10 = EP: endpoint trace\n");
		printf("  0x20 = AP: application trace\n");
		printf("  0x40 = RO: routing trace\n");
	}
	
	


	tbd
	/* send reload command */
	memset(&msg, 0, sizeof(msg));
	msg.message = ADMIN_CALL_SETUP;
	if (argc > 2)
	{
		SCPY(msg.u.call.interface, argv[2]);
	}
	if (argc > 3)
	{
		SCPY(msg.u.call.callerid, argv[3]);
	}
	if (argc > 4)
	{
		SCPY(msg.u.call.dialing, argv[4]);
	}
	if (argc > 5)
	{
		if (argv[5][0] == 'p')
			msg.u.call.present = 1;
	}
	msg.u.call.bc_capa = 0x00; /*INFO_BC_SPEECH*/
	msg.u.call.bc_mode = 0x00; /*INFO_BMODE_CIRCUIT*/
	msg.u.call.bc_info1 = 0;
	msg.u.call.hlc = 0;
	msg.u.call.exthlc = 0;
	if (argc > 6)
		msg.u.call.bc_capa = strtol(argv[6],NULL,0);
	else
		msg.u.call.bc_info1 = 3 | 0x80; /* alaw, if no capability is given at all */
	if (argc > 7) {
		msg.u.call.bc_mode = strtol(argv[7],NULL,0);
		if (msg.u.call.bc_mode) msg.u.call.bc_mode = 2;
	}
	if (argc > 8) {
		msg.u.call.bc_info1 = strtol(argv[8],NULL,0);
		if (msg.u.call.bc_info1 < 0)
			msg.u.call.bc_info1 = 0;
		else
			msg.u.call.bc_info1 |= 0x80;
	}
	if (argc > 9) {
		msg.u.call.hlc = strtol(argv[9],NULL,0);
		if (msg.u.call.hlc < 0)
			msg.u.call.hlc = 0;
		else
			msg.u.call.hlc |= 0x80;
	}
//		printf("hlc=%d\n",  msg.u.call.hlc);
	if (argc > 10) {
		msg.u.call.exthlc = strtol(argv[10],NULL,0);
		if (msg.u.call.exthlc < 0)
			msg.u.call.exthlc = 0;
		else
			msg.u.call.exthlc |= 0x80;
	}

	if (write(sock, &msg, sizeof(msg)) != sizeof(msg))
		return("Broken pipe while sending command.");

	/* receive response */
next:
	if (read(sock, &msg, sizeof(msg)) != sizeof(msg))
		return("Broken pipe while receiving response.");
	switch(msg.message)
	{
		case ADMIN_CALL_SETUP_ACK:
		printf("SETUP ACKNOWLEDGE\n"); fflush(stdout);
		goto next;

		case ADMIN_CALL_PROCEEDING:
		printf("PROCEEDING\n"); fflush(stdout);
		goto next;

		case ADMIN_CALL_ALERTING:
		printf("ALERTING\n"); fflush(stdout);
		goto next;

		case ADMIN_CALL_CONNECT:
		printf("CONNECT\n number=%s\n", msg.u.call.callerid); fflush(stdout);
		goto next;

		case ADMIN_CALL_NOTIFY:
		printf("NOTIFY\n notify=%d\n number=%s\n", msg.u.call.notify, msg.u.call.callerid); fflush(stdout);
		goto next;

		case ADMIN_CALL_DISCONNECT:
		printf("DISCONNECT\n cause=%d %s\n location=%d %s\n", msg.u.call.cause, (msg.u.call.cause>0 && msg.u.call.cause<128)?isdn_cause[msg.u.call.cause].german:"", msg.u.call.location, (msg.u.call.location>=0 && msg.u.call.location<128)?isdn_location[msg.u.call.location].german:""); fflush(stdout);
		goto next;

		case ADMIN_CALL_RELEASE:
		printf("RELEASE\n cause=%d %s\n location=%d %s\n", msg.u.call.cause, (msg.u.call.cause>0 && msg.u.call.cause<128)?isdn_cause[msg.u.call.cause].german:"", msg.u.call.location, (msg.u.call.location>=0 && msg.u.call.location<128)?isdn_location[msg.u.call.location].german:""); fflush(stdout);
		break;

		default:
		return("Response not valid.");
	}
	
	printf("Command successfull.\n");
	return(NULL);
}


/*
 * main function
 */
int main(int argc, char *argv[])
{
	int mode;
	char *socket_name = SOCKET_NAME;
	int sock, conn;
	struct sockaddr_un sock_address;
	char *ret;


	/* show options */
	if (argc <= 1)
	{
		usage:
		printf("\n");
		printf("Usage: %s state | interface | route | dial ...\n", argv[0]);
		printf("state - View current states using graphical console output.\n");
		printf("interface - Tell PBX to reload \"interface.conf\".\n");
		printf("route - Tell PBX to reload \"route.conf\".\n");
		printf("dial <extension> <number> - Tell PBX the next number to dial for extension.\n");
		printf("release <number> - Tell PBX to release endpoint with given number.\n");
		printf("testcall <interface> <callerid> <number> [present|restrict [<capability>]] - Testcall\n");
		printf(" -> capability = <bc> <mode> <codec> <hlc> <exthlc> (Values must be numbers, -1 to omit.)\n");
		printf("trace [brief|short] [<filter> [...]] - Shows call trace. Use filter to reduce output.\n");
		printf(" -> Use 'trace help' to see filter description.\n");
		printf("\n");
		return(0);
	}

	/* check mode */
	if (!(strcasecmp(argv[1],"state")))
	{
		mode = MODE_STATE;
	} else
	if (!(strcasecmp(argv[1],"interface")))
	{
		mode = MODE_INTERFACE;
	} else
	if (!(strcasecmp(argv[1],"route")))
	{
		mode = MODE_ROUTE;
	} else
	if (!(strcasecmp(argv[1],"dial")))
	{
		if (argc <= 3)
			goto usage;
		mode = MODE_DIAL;
	} else
	if (!(strcasecmp(argv[1],"release")))
	{
		if (argc <= 2)
			goto usage;
		mode = MODE_RELEASE;
	} else
	if (!(strcasecmp(argv[1],"testcall")))
	{
		if (argc <= 4)
			goto usage;
		mode = MODE_TESTCALL;
	} else
	if (!(strcasecmp(argv[1],"trace")))
	{
		if (argc <= 2)
			goto usage;
		mode = MODE_TRACE;
	} else
	{
		goto usage;
	}

//pipeagain:
	/* open socket */
	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "Failed to create socket.\n");
		exit(EXIT_FAILURE);
	}
	memset(&sock_address, 0, sizeof(sock_address));
	sock_address.sun_family = PF_UNIX;
	UCPY(sock_address.sun_path, socket_name);
	if ((conn = connect(sock, (struct sockaddr *)&sock_address, SUN_LEN(&sock_address))) < 0)
	{
		close(sock);
		fprintf(stderr, "Failed to connect to socket \"%s\".\nIs PBX4Linux running?\n", sock_address.sun_path);
		exit(EXIT_FAILURE);
	}

	/* process mode */
	switch(mode)
	{
		case MODE_STATE:
		ret = admin_state(sock);
		break;
	
		case MODE_INTERFACE:
		case MODE_ROUTE:
		ret = admin_cmd(sock, mode, NULL, NULL);
		break;

		case MODE_DIAL:
		ret = admin_cmd(sock, mode, argv[2], argv[3]);
		break;

		case MODE_RELEASE:
		ret = admin_cmd(sock, mode, NULL, argv[2]);
		break;

		case MODE_TESTCALL:
		ret = admin_testcall(sock, argc, argv);

		case MODE_TRACE:
		ret = admin_trace(sock, argc, argv);
	}

	close(sock);
	/* now we say good bye */
	if (ret)
	{
//		if (!strncasecmp(ret, "Broken Pipe", 11))
//			goto pipeagain;
		printf("%s\n", ret);
		exit(EXIT_FAILURE);
	}
}





