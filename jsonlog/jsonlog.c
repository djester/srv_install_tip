/*-------------------------------------------------------------------------
 *
 * jsonlog.c
 *		Facility using hook controlling logging output of a Postgres
 *		able to generate JSON logs
 *
 * Copyright (c) 1996-2018, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		jsonlog.c/jsonlog.c
 *
 *-------------------------------------------------------------------------
 */

#include <unistd.h>
#include <sys/time.h>
#include <syslog.h>

#include "postgres.h"
#include "libpq/libpq.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "access/xact.h"
#include "access/transam.h"
#include "lib/stringinfo.h"
#include "postmaster/syslogger.h"
#include "storage/proc.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/json.h"

/* Allow load of this module in shared libs */
PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

/* Hold previous logging hook */
static emit_log_hook_type prev_log_hook = NULL;

/*
 * Track if redirection to syslogger can happen. This uses the same method
 * as postmaster.c and syslogger.c, this flag being updated by the postmaster
 * once server parameters are loaded.
 */
extern bool redirection_done;

/* Log timestamp */
#define LOG_TIMESTAMP_LEN 128
static char log_time[LOG_TIMESTAMP_LEN];

static const char *error_severity(int elevel);
static void write_jsonlog(ErrorData *edata);

/*
 *  * Max string length to send to syslog().  Note that this doesn't count the
 *   * sequence-number prefix we add, and of course it doesn't count the prefix
 *    * added by syslog itself.  Solaris and sysklogd truncate the final message
 *     * at 1024 bytes, so this value leaves 124 bytes for those prefixes.  (Most
 *      * other syslog implementations seem to have limits of 2KB or so.)
 *       */

#ifndef PG_SYSLOG_LIMIT
#define PG_SYSLOG_LIMIT 900
#endif

static bool openlog_done = false;
static char *syslog_ident = NULL;
static int  syslog_facility = LOG_LOCAL0;

static const char *syslog_dest = NULL;

static void write_syslog(int level, const char *line);


/*
 * error_severity
 * Print string showing error severity based on integer level.
 * Taken from elog.c.
 */
static const char *
error_severity(int elevel)
{
	const char *prefix;

	switch (elevel)
	{
		case DEBUG1:
		case DEBUG2:
		case DEBUG3:
		case DEBUG4:
		case DEBUG5:
			prefix = _("DEBUG");
			break;
		case LOG:
		case COMMERROR:
			prefix = _("LOG");
			break;
		case INFO:
			prefix = _("INFO");
			break;
		case NOTICE:
			prefix = _("NOTICE");
			break;
		case WARNING:
			prefix = _("WARNING");
			break;
		case ERROR:
			prefix = _("ERROR");
			break;
		case FATAL:
			prefix = _("FATAL");
			break;
		case PANIC:
			prefix = _("PANIC");
			break;
		default:
			prefix = "???";
			break;
	}

	return prefix;
}

/*
 * write_pipe_chunks
 * Send data to the syslogger using the chunked protocol. Taken from
 * elog.c and simplified as in this case everything is sent to stderr.
 */
static void
write_pipe_chunks(char *data, int len)
{
	PipeProtoChunk	p;
	int				fd = fileno(stderr);
	int				rc;

	Assert(len > 0);

	p.proto.nuls[0] = p.proto.nuls[1] = '\0';
	p.proto.pid = MyProcPid;

	/* write all but the last chunk */
	while (len > PIPE_MAX_PAYLOAD)
	{
		p.proto.is_last = 'f';
		p.proto.len = PIPE_MAX_PAYLOAD;
		memcpy(p.proto.data, data, PIPE_MAX_PAYLOAD);
		rc = write(fd, &p, PIPE_HEADER_SIZE + PIPE_MAX_PAYLOAD);
		(void) rc;
		data += PIPE_MAX_PAYLOAD;
		len -= PIPE_MAX_PAYLOAD;
	}

	/* write the last chunk */
	p.proto.is_last = 't';
	p.proto.len = len;
	memcpy(p.proto.data, data, len);
	rc = write(fd, &p, PIPE_HEADER_SIZE + len);
	(void) rc;
}

/*
 * write_console
 * Send data to stderr, there is nothing fancy here.
 */
static void
write_console(char *data, int len)
{
	int		 fd = fileno(stderr);
	int		 rc;

	Assert(len > 0);
	rc = write(fd, data, PIPE_HEADER_SIZE + len);
	(void) rc;
}

static void
setup_formatted_log_time(void)
{
	struct timeval tv;
	pg_time_t   stamp_time;
	char		msbuf[8];

	gettimeofday(&tv, NULL);
	stamp_time = (pg_time_t) tv.tv_sec;

	/*
	 * Note: we expect that guc.c will ensure that log_timezone is set up (at
	 * least with a minimal GMT value) before Log_line_prefix can become
	 * nonempty or CSV mode can be selected.
	 */
	pg_strftime(log_time, LOG_TIMESTAMP_LEN,
				/* leave room for milliseconds... */
				"%Y-%m-%d %H:%M:%S	 %Z",
				pg_localtime(&stamp_time, log_timezone));

	/* 'paste' milliseconds into place... */
	sprintf(msbuf, ".%03d", (int) (tv.tv_usec / 1000));
	strncpy(log_time + 19, msbuf, 4);
}

/*
 * appendJSONLiteral
 * Append to given StringInfo a JSON with a given key and a value
 * not yet made literal.
 */
static void
appendJSONLiteral(StringInfo buf, char *key, char *value, bool is_comma)
{
	StringInfoData literal_json;

	initStringInfo(&literal_json);
	Assert(key && value);

	/*
	 * Call in-core function able to generate wanted strings, there is
	 * no need to reinvent the wheel.
	 */
	escape_json(&literal_json, value);

	/* Now append the field */
	appendStringInfo(buf, "\"%s\":%s", key, literal_json.data);

	/* Add comma if necessary */
	if (is_comma)
		appendStringInfoChar(buf, ',');

	/* Clean up */
	pfree(literal_json.data);
}

/*
 *  * Write a message line to syslog
 *  * func from elog.c from PostgreSQL src
 *   */
static void
write_syslog(int level, const char *line)
{
    static unsigned long seq = 0;

    int         len;
    const char *nlpos;

    /* Open syslog connection if not done yet */
    if (!openlog_done)
    {
        openlog(syslog_ident ? syslog_ident : "postgres",
                LOG_PID | LOG_NDELAY | LOG_NOWAIT,
                syslog_facility);
        openlog_done = true;
    }

    /*
 *      * We add a sequence number to each log message to suppress "same"
 *           * messages.
 *                */
    seq++;

    /*
 *      * Our problem here is that many syslog implementations don't handle long
 *           * messages in an acceptable manner. While this function doesn't help that
 *                * fact, it does work around by splitting up messages into smaller pieces.
 *                     *
 *                          * We divide into multiple syslog() calls if message is too long or if the
 *                               * message contains embedded newline(s).
 *                                    */
    len = strlen(line);
    nlpos = strchr(line, '\n');
    if (len > PG_SYSLOG_LIMIT || nlpos != NULL)
    {
        int         chunk_nr = 0;

        while (len > 0)
        {
            char        buf[PG_SYSLOG_LIMIT + 1];
            int         buflen;
            int         i;

            /* if we start at a newline, move ahead one char */
            if (line[0] == '\n')
            {
                line++;
                len--;
                /* we need to recompute the next newline's position, too */
                nlpos = strchr(line, '\n');
                continue;
            }

            /* copy one line, or as much as will fit, to buf */
            if (nlpos != NULL)
                buflen = nlpos - line;
            else
                buflen = len;
            buflen = Min(buflen, PG_SYSLOG_LIMIT);
            memcpy(buf, line, buflen);
            buf[buflen] = '\0';

            /* trim to multibyte letter boundary */
            buflen = pg_mbcliplen(buf, buflen, buflen);
            if (buflen <= 0)
                return;
            buf[buflen] = '\0';

            /* already word boundary? */
            if (line[buflen] != '\0' &&
                !isspace((unsigned char) line[buflen]))
            {
                /* try to divide at word boundary */
                i = buflen - 1;
                while (i > 0 && !isspace((unsigned char) buf[i]))
                    i--;

                if (i > 0)      /* else couldn't divide word boundary */
                {
                    buflen = i;
                    buf[i] = '\0';
                }
            }

            chunk_nr++;

            syslog(level, "[%lu-%d] %s", seq, chunk_nr, buf);
            line += buflen;
            len -= buflen;
        }
    }
    else
    {
        /* message short enough */
         syslog(level, "[%lu] %s", seq, line);
        //syslog(level, "%s", line);
    }
}




/*
 * write_jsonlog
 * Write logs in json format.
 */
static void
write_jsonlog(ErrorData *edata)
{
	StringInfoData	buf;
	TransactionId	txid = GetTopTransactionIdIfAny();

	/*
 	* Get Log_destination parameter value
 	*/  

	syslog_dest = GetConfigOption("log_destination", false, false);

	/*
	 * Disable logs to server, we don't want duplicate entries in
	 * the server.
	 */
	edata->output_to_server = false;

	/*
	 * Nothing to do if log message has a severity lower than the minimum
	 * wanted.
	 */
	if (edata->elevel < log_min_messages)
		return;

	initStringInfo(&buf);

	/* Initialize string */
	appendStringInfoChar(&buf, '{');

	if (strcmp(syslog_dest,"syslog") == 0)
	{
		/* Username */
		if (MyProcPort && MyProcPort->user_name)
			appendJSONLiteral(&buf, "user", MyProcPort->user_name, true);

		/* Database name */
		if (MyProcPort && MyProcPort->database_name)
			appendJSONLiteral(&buf, "dbname", MyProcPort->database_name, true);

                /* Session id */
                if (MyProcPid != 0)
                        appendStringInfo(&buf, "\"session_id\":\"%lx.%x\",",
                                                         (long) MyStartTime, MyProcPid);

                /* Virtual transaction id */
                /* keep VXID format in sync with lockfuncs.c */
                if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
                        appendStringInfo(&buf, "\"vxid\":\"%d/%u\",",
                                                         MyProc->backendId, MyProc->lxid);

                /* Transaction id */
                if (txid != InvalidTransactionId)
                        appendStringInfo(&buf, "\"txid\":%u,", GetTopTransactionIdIfAny());

                /* SQL state code */
                if (edata->sqlerrcode != ERRCODE_SUCCESSFUL_COMPLETION)
                        appendJSONLiteral(&buf, "state_code",
                                                          unpack_sql_state(edata->sqlerrcode), true);

                /* Error detail or Error detail log */
                if (edata->detail_log)
                        appendJSONLiteral(&buf, "detail_log", edata->detail_log, true);
                else if (edata->detail)
                        appendJSONLiteral(&buf, "detail", edata->detail, true);

                /* Error hint */
                if (edata->hint)
                        appendJSONLiteral(&buf, "hint", edata->hint, true);

                /* Internal query */
                if (edata->internalquery)
                        appendJSONLiteral(&buf, "internal_query",
                                                          edata->internalquery, true);

                /* Error context */
                if (edata->context)
                        appendJSONLiteral(&buf, "context", edata->context, true);

                /* File error location */
                if (Log_error_verbosity >= PGERROR_VERBOSE)
                {
                        StringInfoData msgbuf;

                        initStringInfo(&msgbuf);

                        if (edata->funcname && edata->filename)
                                appendStringInfo(&msgbuf, "%s, %s:%d",
                                                                 edata->funcname, edata->filename,
                                                                 edata->lineno);
                        else if (edata->filename)
                                appendStringInfo(&msgbuf, "%s:%d",
                                                                 edata->filename, edata->lineno);
                        appendJSONLiteral(&buf, "file_location", msgbuf.data, true);
                        pfree(msgbuf.data);
                }

                /* Application name */
                if (application_name && application_name[0] != '\0')
                        appendJSONLiteral(&buf, "application_name",
                                                          application_name, true);


		/* Error message */
		appendJSONLiteral(&buf, "message", edata->message, false);

		/* Finish string */
		appendStringInfoChar(&buf, '}');
		appendStringInfoChar(&buf, '\n');

	//	write_syslog(edata->elevel, edata->message);
		write_syslog(edata->elevel, buf.data);

	} else
	{

		/* Timestamp */
		if (log_time[0] == '\0')
			setup_formatted_log_time();
		appendJSONLiteral(&buf, "timestamp", log_time, true);

		/* Username */
		if (MyProcPort && MyProcPort->user_name)
			appendJSONLiteral(&buf, "user", MyProcPort->user_name, true);

		/* Database name */
		if (MyProcPort && MyProcPort->database_name)
			appendJSONLiteral(&buf, "dbname", MyProcPort->database_name, true);

		/* Process ID */
		if (MyProcPid != 0)
			appendStringInfo(&buf, "\"pid\":%d,", MyProcPid);

		/* Remote host and port */
		if (MyProcPort && MyProcPort->remote_host)
		{
			appendJSONLiteral(&buf, "remote_host",
							  MyProcPort->remote_host, true);
			if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
				appendJSONLiteral(&buf, "remote_port",
								  MyProcPort->remote_port, true);
		}

		/* Session id */
		if (MyProcPid != 0)
			appendStringInfo(&buf, "\"session_id\":\"%lx.%x\",",
							 (long) MyStartTime, MyProcPid);

		/* Virtual transaction id */
		/* keep VXID format in sync with lockfuncs.c */
		if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
			appendStringInfo(&buf, "\"vxid\":\"%d/%u\",",
							 MyProc->backendId, MyProc->lxid);

		/* Transaction id */
		if (txid != InvalidTransactionId)
			appendStringInfo(&buf, "\"txid\":%u,", GetTopTransactionIdIfAny());

		/* Error severity */
		appendJSONLiteral(&buf, "error_severity",
						  (char *) error_severity(edata->elevel), true);

		/* SQL state code */
		if (edata->sqlerrcode != ERRCODE_SUCCESSFUL_COMPLETION)
			appendJSONLiteral(&buf, "state_code",
							  unpack_sql_state(edata->sqlerrcode), true);

		/* Error detail or Error detail log */
		if (edata->detail_log)
			appendJSONLiteral(&buf, "detail_log", edata->detail_log, true);
		else if (edata->detail)
			appendJSONLiteral(&buf, "detail", edata->detail, true);

		/* Error hint */
		if (edata->hint)
			appendJSONLiteral(&buf, "hint", edata->hint, true);

		/* Internal query */
		if (edata->internalquery)
			appendJSONLiteral(&buf, "internal_query",
							  edata->internalquery, true);

		/* Error context */
		if (edata->context)
			appendJSONLiteral(&buf, "context", edata->context, true);

		/* File error location */
		if (Log_error_verbosity >= PGERROR_VERBOSE)
		{	
			StringInfoData msgbuf;

			initStringInfo(&msgbuf);

			if (edata->funcname && edata->filename)
				appendStringInfo(&msgbuf, "%s, %s:%d",
								 edata->funcname, edata->filename,
								 edata->lineno);
			else if (edata->filename)
				appendStringInfo(&msgbuf, "%s:%d",
								 edata->filename, edata->lineno);
			appendJSONLiteral(&buf, "file_location", msgbuf.data, true);
			pfree(msgbuf.data);
		}

		/* Application name */
		if (application_name && application_name[0] != '\0')
			appendJSONLiteral(&buf, "application_name",
							  application_name, true);

		/* Error message */
		appendJSONLiteral(&buf, "message", edata->message, false);

		/* Finish string */
		appendStringInfoChar(&buf, '}');
		appendStringInfoChar(&buf, '\n');

		/* Write to stderr, if enabled */
	        if ((Log_destination & LOG_DESTINATION_STDERR) != 0) 
        	//if ((Log_destination & LOG_DESTINATION_SYSLOG) != 0) 
		{
			if (Logging_collector && redirection_done && !am_syslogger)
				write_pipe_chunks(buf.data, buf.len);
			else
				write_console(buf.data, buf.len);
		}
	
		/* If in the syslogger process, try to write messages direct to file */
		if (am_syslogger)
			write_syslogger_file(buf.data, buf.len, LOG_DESTINATION_STDERR);
	}

	/* Cleanup */
	pfree(buf.data);

	/* Continue chain to previous hook */
	if (prev_log_hook)
		(*prev_log_hook) (edata);
}

/*
 * _PG_init
 * Entry point loading hooks
 */
void
_PG_init(void)
{
	prev_log_hook = emit_log_hook;
	emit_log_hook = write_jsonlog;
}

/*
 * _PG_fini
 * Exit point unloading hooks
 */
void
_PG_fini(void)
{
	emit_log_hook = prev_log_hook;
}
