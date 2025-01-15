#include <u.h>
#include <libc.h>
#include <bio.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>
#include <ndb.h>
#include <json.h>

#define KASAON "{\"system\":{\"set_relay_state\":{\"state\":1}}}"
#define KASAOFF "{\"system\":{\"set_relay_state\":{\"state\":0}}}"
#define KINFO "{\"system\":{\"get_sysinfo\":null},\"emeter\":{\"get_realtime\":null}}"
#define NOBULB "Plug unreachable ☹"


static void fsread(Req *r);
static void fswrite(Req *r);
static void fsstart(Srv*);
static void fsend(Srv*);


typedef struct Bulbcmd Bulbcmd;

struct Bulbcmd
{
	char *key;
	char *value;
};


Srv fs = 
{
	.start=fsstart,
	.read=fsread,
	.write=fswrite,
	.end=fsend,
};

int debug = 0;


/* encrypt and prefix size */
static int
kenc(char *in, char *out, int n)
{
	char temp[128];
	char k = 0xAB;
	char x;
	int i;

	for(i = 0; i < n; i++){
		x = k ^ in[i];
		k = x;
		temp[i] = x;
	}

/* size is 32 bit big-endian */
	out[0] = (n & 0xFF000000) >> 24;
	out[1] = (n & 0xFF0000) >> 16;
	out[2] = (n & 0xFF00) >> 8;
	out[3] = (n & 0xFF);

/* add payload after size */
	strcpy((char*)out+4, (char*)temp);

/* return command length + size prefix */
	return i + 4;
}


/* removed length prefix and decrypt */
static int
kdec(char *in, char *out, int n)
{
	char k = 0xAB;
	char x;
	char *temp = in + 4;	/* start after size prefix */
	int i;

/* subtract 4 bytes for size prefix */
	n -= 4;

	for(i = 0; i < n; i++){
		x = k ^ temp[i];
		k = temp[i];
		out[i] = x;
	}

/* return decrypted command length */
	return i;
}


void
timeout(void *, char *msg)
{
	if(strstr("alarm", msg) != nil)
		noted(NCONT);
	else
		noted(NDFLT);
}


static int
callkasa(char *name, char *cmd, char *reply, long rsize)
{
	int fd, n, c;
	n = c = 0;
	char *buf;

	if(debug)
		print("name: %s\ncmd %s\nmkaddr %s\n", name, cmd, netmkaddr(name, "upd", "9999"));
	
	buf = emalloc9p(2048);

	c = kenc(cmd, buf, strlen(cmd));

	notify(timeout);
	alarm(1000);

	fd = dial(netmkaddr(name, "tcp", "9999"), nil, nil, nil);
	write(fd, buf, c);
	sleep(10);
	memset(buf, 0, sizeof(buf));
	n = read(fd, buf, 2048);

	alarm(0);

	if(n)
		c = kdec(buf, reply, n);

	if(debug)
		print("fd is %d\nreply %s\n", fd, buf);

	free(buf);
	close(fd);
	return(c);
}


static int
jtoresult(JSON *jreply, char *out, int nout)
{

	JSON *jresult, *jres2, *jres3, *jres4;
	JSONEl *jp;
	char *p;
	int n = 0;

	jresult = jsonbyname(jreply, "system");

	if(jresult == nil){
		print("no jresult\n");
		return 0;
	}

	jres2 = jsonbyname(jresult, "get_sysinfo");

	if(jres2 == nil){
		print("no jres2\n");
		return 0;
	}

	jp = jres2->first;
	p = out;

	while(jp != nil){
		p = seprint(p, out + nout, jp->name);

		switch(jp->val->t){
		case JSONNull:
			p = seprint(p, out + nout, "=‽\n");
			break;
		case JSONBool:
			p = seprint(p, out + nout, "=%s\n", jp->val->n ? "true" : "false");
			break;
		case JSONNumber:
			p = seprint(p, out + nout, "=%.f\n", jp->val->n);
			break;
		case JSONString:
			p = seprint(p, out + nout, "=%s\n", jp->val->s);
			break;
		}
		n++;
		jp = jp->next;
	}

	jres3 = jsonbyname(jreply, "emeter");

	if(jres3 == nil){
		print("no jres3\n");
		return 0;
	}

	jres4 = jsonbyname(jres3, "get_realtime");

	if(jres4 == nil){
		print("no jres4\n");
		return 0;
	}

	jp = jres4->first;

	while(jp != nil){
		p = seprint(p, out + nout, jp->name);

		switch(jp->val->t){
		case JSONNull:
			p = seprint(p, out + nout, "=‽\n");
			break;
		case JSONBool:
			p = seprint(p, out + nout, "=%s\n", jp->val->n ? "true" : "false");
			break;
		case JSONNumber:
			p = seprint(p, out + nout, "=%.f\n", jp->val->n);
			break;
		case JSONString:
			p = seprint(p, out + nout, "=%s\n", jp->val->s);
			break;
		}
		n++;
		jp = jp->next;
	}


	USED(p);
	USED(jp);
	return(n);

}

static int
jtoerror(JSON *jreply, char *error)
{
	JSON *jsys, *jstate, *jerror;
	int n = 0;

	jsys = jsonbyname(jreply, "system");
	jstate = jsonbyname(jsys, "set_relay_state");

	if(jstate != nil)
		jerror = jsonbyname(jstate, "err_code");

	return(jerror->n);
}


int
makekasacmd(char *input, char *out, long nout)
{
	Bulbcmd bc[16];

	char *pair[16];
	char *command[2];
	char *p;

	int i, ti, ci;

	if(debug)
		print("input %s\n", input);

	ti = tokenize(input, pair, 16);

	if(!ti)
		return(ti);

	for(i = 0; i < ti; i++){
		ci = getfields(pair[i], command, 2, 1, "=");
		if(ci == 2){
			bc[i].key = command[0];
			bc[i].value = command[1];
		}
		else{
			bc[i].key = command[0];
			if(!strcmp(bc[0].key, "on")){
				strcpy(out, KASAON);
				return(1);
			}else if(!strcmp(bc[0].key, "off")){
				strcpy(out, KASAOFF);
				return(1);
			}
			return(0);
		}
	}

/* other options later */

	return(0);
}


static void
fsstart(Srv*)
{
	Ndb *bulbndb;
	Ndbs s;
	Ndbtuple *bulbtp;
	char *sysname;
	char *user;

	File *root;
	File *wizdir;

	/* this assumes the system name "sys=" is the first entry for a line in ndb/local */
	/* all bulbs on the network must have "kasa=plug" to be included in the file system */

	user = getuser();
	fs.tree = alloctree(user, user, 0555, nil);

	root = fs.tree->root;

	wizdir = createfile(root, "kasa", user, DMDIR|0555, nil);

	bulbndb = ndbopen(0);

	for(bulbtp = ndbsearch(bulbndb, &s, "kasa", "plug"); bulbtp != nil; bulbtp = ndbsnext(&s, "kasa", "plug")){
		sysname = bulbtp->val;
		createfile(wizdir, sysname, user, 0666, nil);
	}

	ndbclose(bulbndb);
}


static void
fsread(Req *r)
{
	char kasareply[1024];
	JSON *jreply;
	char waserror[64];
	char *rerror;
	char *kasaname;
	char readout[1024];
	int errint;

	memset(kasareply, 0, 1024);
	memset(readout, 0, 1024);
	rerror = nil;

	kasaname = r->fid->file->name;

	if(callkasa(kasaname, KINFO, kasareply, 1024) < 1){
		respond(r, NOBULB);
		return;
	}

	jreply = jsonparse(kasareply);

	if(jtoresult(jreply, readout, sizeof(readout)) < 1){
		errint = jtoerror(jreply, waserror);
		rerror = "Need Better Read Error";
	}

	readstr(r, readout);
	jsonfree(jreply);

	respond(r, rerror);
}


static void
fswrite(Req *r)
{
	int n;
	char *input, *rerror, *kasacmd, *kasareply;
	char waserror[64];
	JSON *jreply;

	rerror = nil;

	n = r->ofcall.count = r->ifcall.count;
	input = emalloc9p(n+1);
	memmove(input, r->ifcall.data, n);

	kasacmd = emalloc9p(2048);
	kasareply = emalloc9p(2048);

	if(makekasacmd(input, kasacmd, sizeof(kasacmd)) < 1){
		rerror = "makekasacmd failed";
		goto Endwrite;
	}

	if(callkasa(r->fid->file->name, kasacmd, kasareply, sizeof(kasareply)) < 1){
		rerror = NOBULB;
		goto Endwrite;
	}

	jreply = jsonparse(kasareply);

	if(jtoerror(jreply, waserror))
		rerror = waserror;

	jsonfree(jreply);

Endwrite:
	respond(r, rerror);
	free(input);
	free(kasacmd);
	free(kasareply);
}


static void
fsend(Srv*)
{
	postnote(PNGROUP, getpid(), "shutdown");
	threadexitsall(nil);
}



static void
usage(void)
{
	fprint(2, "usage: %s [-d] [-m mtpt] [-s service]\n", argv0);
	exits("usage");
}


void
threadmain(int argc, char *argv[])
{
	char *mtpt;
	char *service;

	mtpt = "/n";
	service = "kasafs";

	ARGBEGIN {
	case 'm':
		mtpt = EARGF(usage());
		break;
	case 's':
		service = EARGF(usage());
		break;
	case 'd':
		debug++;
		break;
	default:
		usage();
	} ARGEND;

	threadpostmountsrv(&fs, service, mtpt, MREPL);
	threadexits(nil);
}
