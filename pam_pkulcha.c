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

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  char srcFile[1024];
	char logstr[1024];
	if (argc < 2) {
		strcpy(srcFile, "/etc/security/pam_pkulcha.txt");
	}
	else {
	  strcpy(srcFile, argv[1]);
	}
	/*sprintf(logstr, "srcFile: %s\n", srcFile);*/
	// syslog(LOG_MAKEPRI(LOG_AUTHPRIV,LOG_INFO), "srcFile: %s\n", srcFile);
	pam_syslog(pamh, LOG_CRIT, "srcFile: %s\n", srcFile);
	return(PAM_SUCCESS);
	return(PAM_AUTH_ERR);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_SUCCESS);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}
