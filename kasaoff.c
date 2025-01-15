#include <u.h>
#include <libc.h>
#include <json.h>


#define KASAOFF "{\"system\":{\"set_relay_state\":{\"state\":0}}}"


void
kenc(char *in, char *out, int n)
{
	char hold[256];
	char key = 0xAB;
	char temp;
	int i;

	for(i = 0; i < n; i++){
		temp = key ^ in[i];
		key = temp;
		hold[i] = temp;
	}

	out[0] = (n & 0xFF000000) >> 24;
	out[1] = (n & 0xFF0000) >> 16;
	out[2] = (n & 0xFF00) >> 8;
	out[3] = (n & 0xFF);

	strcpy((char*)out+4, (char*)hold);
}


void
kdec(char *in, char *out, int n)
{
	char key = 0xAB;
	char temp;
	char *foo = in + 4;
	int i;

	n -= 4;

	for(i = 0; i < n; i++){
		temp = key ^ foo[i];
		key = foo[i];
		out[i] = temp;
	}
}


int
doparse(JSON *jreply, char *out, int nout)
{

	JSON *jresult, *jres2;
	JSONEl *jp;
	char *p;
	int n = 0;

	jresult = jsonbyname(jreply, "system");

	if(jresult == nil){
		print("no jresult\n");
		return 0;
	}

	jres2 = jsonbyname(jresult, "set_relay_state");

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

	USED(p);
	USED(jp);
	return(n);

}


void
main(int argc, char *argv[])
{
	int fd, n;
	char buf[256], cmd[256];
	char rout[2048], rply[2048], rbuf[2048];
	JSON *jreply;

	print("powoff on %s\n", argv[1]);

	if((fd = dial(netmkaddr(argv[1], "tcp", "9999"), nil, nil, nil)) < 1){
		sysfatal("dial failed");
	}

	n = sprint(buf, KASAOFF);
	kenc(buf, cmd, n);
	n = write(fd, cmd, n+4);

	memset(rply, 0, sizeof(rply));
	memset(rbuf, 0, sizeof(rbuf));

	sleep(10);

	n = read(fd, rply, sizeof(rply));

	kdec(rply, rbuf, n);

	jreply = jsonparse(rbuf);

	if(jreply != nil){
		doparse(jreply, rout, sizeof(rout));
		print(rout);
	}

	close(fd);
	jsonfree(jreply);

	exits(nil);
}
