/*
 * dracinsert.c - Command line utility to add ip addrs to drac.
 *		- Copyright 2006, Jesse Norell
 *		- Copyright 2006, Kentec Communications, Inc.
 *
 * compile:  gcc -Wall -O2 -o dracinsert dracinsert.c -ldrac 
 *
 * license:  free for you to have/use/distribute/whatever
 */

/*
 * v 0.00   Wed Oct  4 10:45:59 MDT 2006
 *	- initial version, just trying to get something to work
 *	- the drac server needs to authenticate the client so that users
 *	  can't add arbitrary ip addrs to the database.  this can be
 *	  setup to only run as root or setuid, but that's hardly a fix
 *	  for the root issue.
 */

/*
 * Todo:
 *	- add #ifdefs to allow overriding hostname and user/group
 *	  at compile time
 *	- allow members of ALLOW_GROUP to run
 *	- allow hostnames to be specified on command line and dns
 *	  lookup done for their addr(s) (?)
 *	- add support to drac server to remove entries
 */

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DRAC_SERVER "localhost"
#define ALLOW_USER "root"
#define ALLOW_GROUP "wheel"
#undef REQUIRE_SUID

char *dracserv = DRAC_SERVER;

void usage() {
	printf("usage:  dracinsert ([-h] | [-s drac_server] xx.xx.xx.xx [...])\n");
}

void die(char *s) {
        openlog("dracinsert", LOG_PID|LOG_CONS, LOG_AUTHPRIV);
        syslog(LOG_ALERT,
            "failed - reason: %.60s, uid(%d) euid(%d) gid(%d) egid(%d)\n",
            s,
            (uid_t)getuid(),
            (uid_t)geteuid(),
            (gid_t)getgid(),
            (gid_t)getegid());
        closelog();

        exit(1);
}


void dracinsert(char *s) {
	struct in_addr inp;
 	char *err;
	
        openlog("dracinsert", LOG_PID, LOG_AUTH);

	if (strlen(s) > 16) {
	    s[16]='\0';
            syslog(LOG_INFO, "invalid addr: %s\n", s);
            closelog();
	    return;
	}

	if (inet_aton(s, &inp)) {
            syslog(LOG_INFO, "adding addr: %s\n", s);
	} else {
            syslog(LOG_INFO, "invalid addr: %s\n", s);
            closelog();
	    return;
	}

 	if (dracauth(dracserv, inp, &err) != 0)
            syslog(LOG_NOTICE, "dracauth(%s) failed: %s\n", s, err);

        closelog();
	return;

}

int
main (int argc, char *argv[]) {
        struct passwd *pwent;
	int opt;

	/* Todo: need to allow members of ALLOW_GROUP */

        pwent = getpwnam(ALLOW_USER);
	if (pwent) {
            if ( (uid_t)getuid() != 0 && (uid_t)getuid() != pwent->pw_uid)
                die("User not allowed to run this program");
	} else {
            if ( (uid_t)getuid() != 0 )
                die("User not allowed to run this program");
	}

#ifdef REQUIRE_SUID
        if ( (uid_t)geteuid() != 0 )
                die("Not root and not setuid");
#endif

	while ((opt = getopt(argc, argv, "hs:")) != -1) {
	    switch (opt) {
		  case 'h':
			usage();
			return 0;
		  case 's':
			if (optarg && strlen(optarg) > 0)
			  dracserv = strdup(optarg);
			else {
			  usage();
			  return 1;
			}
			break;
                  default:
                        break;
            }
        }

        if (optind < argc)
	    while (optind < argc)
		dracinsert(argv[optind++]);
	else {
	    usage();
	    return 1;
	}

        return(0);
}

