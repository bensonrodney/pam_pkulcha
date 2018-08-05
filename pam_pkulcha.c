#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#ifdef HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#  include <security/pam_modules.h>
#endif
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <time.h>

char* random_line_from_file(const char* filename) {
	/* shamelessly copied from:
	   https://stackoverflow.com/questions/40118509/read-random-line-from-txt-file
	 */
	FILE *f;
	size_t lineno = 0;
	size_t selectlen;
	char selected[256]; /* Arbitrary, make it whatever size makes sense */
	char current[256];
	selected[0] = '\0'; /* Don't crash if file is empty */
	double rnd;

  srand(time(NULL));

	f = fopen(filename, "r"); /* Add your own error checking */
	while (fgets(current, sizeof(current), f)) {
		  rnd = (double)rand()/RAND_MAX;
			if (rnd < (1.0 / (double)(++lineno))) {
				  printf("########## if condition met. rnd %.03f line %d\n", rnd, (int)lineno);
					strcpy(selected, current);
			}
	}
	fclose(f);
	selectlen = strlen(selected);
	if (selectlen > 0 && selected[selectlen-1] == '\n') {
			selected[selectlen-1] = '\0';
	}
	return strdup(selected);
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	char srcFile[1024];
	if (argc < 2) {
		strcpy(srcFile, "/etc/security/pam_pkulcha.txt");
	}
	else {
	  strcpy(srcFile, argv[1]);
	}
	pam_syslog(pamh, LOG_INFO, "srcFile: %s\n", srcFile);
	char *chalresp = random_line_from_file(srcFile);
	pam_syslog(pamh, LOG_INFO, "challenge/response line: %s", chalresp);
	return(PAM_SUCCESS);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}
