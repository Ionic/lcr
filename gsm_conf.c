/*****************************************************************************\
**                                                                           **
** PBX4Linux                                                                 **
**                                                                           **
**---------------------------------------------------------------------------**
** Copyright: Andreas Eversberg                                              **
**                                                                           **
** reading options.conf and filling structure                                **
**                                                                           **
\*****************************************************************************/ 

#include "main.h"
#include "openbsc/openbsc.h"


char *gsm_conf_error = "";

/* read options
 *
 * read options from options.conf
 */
int gsm_conf(struct gsm_conf *gsm_conf)
{
	FILE *fp=NULL;
	char filename[128];
	char *p;
	char option[32];
	char params[11][256];
	int pnum;
	unsigned int line,i;
	char buffer[256];

	/* set defaults */
	SCPY(gsm_conf->debug, "");
	SCPY(gsm_conf->interface_bsc, "mISDN_l1loop.1");
	SCPY(gsm_conf->interface_lcr, "mISDN_l1loop.2");
	SCPY(gsm_conf->short_name, "LCR");
	SCPY(gsm_conf->long_name, "Linux-Call-Router");
	gsm_conf->mcc = 1;
	gsm_conf->mnc = 1;
	gsm_conf->lac = 1;
	SCPY(gsm_conf->hlr, "hlr.sqlite3");
	gsm_conf->allow_all = 0;
	gsm_conf->keep_l2 = 0;
	gsm_conf->numbts = 0;
	//gsm_conf->bts[xx]
	gsm_conf->noemergshut = 0;

	SPRINT(filename, "%s/gsm.conf", CONFIG_DATA);

	if (!(fp=fopen(filename,"r")))
	{
		SPRINT(gsm_conf_error, "Cannot open %s\n",filename);
		return(0);
	}

	line=0;
	while((fgets(buffer,sizeof(buffer),fp)))
	{
		line++;
		buffer[sizeof(buffer)-1]=0;
		if (buffer[0]) buffer[strlen(buffer)-1]=0;
		p=buffer;

		while(*p <= 32) /* skip spaces */
		{
			if (*p == 0)
				break;
			p++;
		}
		if (*p==0 || *p=='#') /* ignore comments and empty line */
			continue;

		option[0]=0;
		i=0; /* read option */
		while(*p > 32)
		{
			if (i+1 >= sizeof(option))
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): option too long.\n",filename,line);
				goto error;
			}
			option[i+1] = '\0';
			option[i++] = *p++;
		}

		while(*p <= 32) /* skip spaces */
		{
			if (*p == 0)
				break;
			p++;
		}

		params[0][0] = 0;
		pnum = 0;
		while(*p!=0 && *p!='#' && pnum < 10) /* param */
		{
			i=0; /* read param */
			while(*p > 32)
			{
				if (i+1 >= sizeof(params[pnum]))
				{
					SPRINT(gsm_conf_error, "Error in %s (line %d): param too long.\n",filename,line);
					goto error;
				}
				params[pnum][i+1] = '\0';
				params[pnum][i++] = *p++;
			}
			while(*p <= 32) /* skip spaces */
			{
				if (*p == 0)
					break;
				p++;
			}
			pnum++;
			params[pnum][0] = 0;
		}

		/* at this point we have option and param */

		/* check option */
		if (!strcmp(option,"debug"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line,option);
				goto error;
			}
			SCPY(gsm_conf->debug, params[0]);

		} else
		if (!strcmp(option,"interface-bsc"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			SCPY(gsm_conf->interface_bsc, params[0]);

		} else
		if (!strcmp(option,"interface-lcr"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			SCPY(gsm_conf->interface_lcr, params[0]);

		} else
		if (!strcmp(option,"short-name"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			SCPY(gsm_conf->short_name, params[0]);

		} else
		if (!strcmp(option,"long-name"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			SCPY(gsm_conf->long_name, params[0]);

		} else
		if (!strcmp(option,"mcc"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			gsm_conf->mcc = atoi(params[0]);

		} else
		if (!strcmp(option,"mnc"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			gsm_conf->mnc = atoi(params[0]);

		} else
		if (!strcmp(option,"lac"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			gsm_conf->lac = atoi(params[0]);

		} else
		if (!strcmp(option,"hlr"))
		{
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter for option %s missing.\n",filename,line, option);
				goto error;
			}
			SCPY(gsm_conf->hlr, params[0]);

		} else
		if (!strcmp(option,"allow-all"))
		{
			gsm_conf->allow_all = 1;
		} else
		if (!strcmp(option,"keep-l2"))
		{
			gsm_conf->keep_l2 = 1;

		} else
		if (!strcmp(option,"no-mergency-shutdown"))
		{
			gsm_conf->noemergshut = 1;
		} else
		if (!strcmp(option,"bts"))
		{
			if (gsm_conf->numbts == 8)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): too many BTS defined.\n",filename,line);
				goto error;
			}
			if (params[0][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter <bts-type> for option %s missing.\n",filename,line,option);
				goto error;
			}
			if (params[1][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter <card number> for option %s missing.\n",filename,line,option);
				goto error;
			}
			if (params[2][0]==0)
			{
				SPRINT(gsm_conf_error, "Error in %s (line %d): parameter <frequency> for option %s missing.\n",filename,line,option);
				goto error;
			}
			if (!strcmp(params[0], "bs11"))
			{
				gsm_conf->bts[gsm_conf->numbts].type = GSM_BTS_TYPE_BS11;
			} else {
				SPRINT(gsm_conf_error, "Error in %s (line %d): unknown BTS type '%s'.\n",filename,line,params[0]);
				goto error;
			}
			gsm_conf->bts[gsm_conf->numbts].card = atoi(params[1]);
			gsm_conf->bts[gsm_conf->numbts].numtrx = 0;
			while (params[gsm_conf->bts[gsm_conf->numbts].numtrx+2][0])
			{
				if (gsm_conf->bts[gsm_conf->numbts].numtrx == 8)
				{
					SPRINT(gsm_conf_error, "Error in %s (line %d): too many frequencies defined.\n",filename,line);
					goto error;
				}
				gsm_conf->bts[gsm_conf->numbts].frequency[gsm_conf->bts[gsm_conf->numbts].numtrx++] = atoi(params[gsm_conf->bts[gsm_conf->numbts].numtrx+2]);
			}
			gsm_conf->numbts++;
		} else
		{
			SPRINT(gsm_conf_error, "Error in %s (line %d): wrong option keyword %s.\n", filename,line,option);
			goto error;
		}
	}

	if (fp) fclose(fp);
	return(1);
error:
	if (fp) fclose(fp);
	return(0);
}


