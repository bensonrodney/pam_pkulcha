/* pam_pkulcha.c (sounds like 'pop culture'?)
 * Jason Milen - Aug 2018
 *
 * WARNING! THIS MODULE SHOULD NOT FORM A CRITICAL PART OF YOUR AUTHENTICATION
 *          SYSTEM! It can be added as a required or optional module in your
 *          PAM configs but do not rely on it.
 * This PAM module was written purely as an exercise for me to learn about
 * PAM and in the end is just a bit of fun and is really quite useless.
 *
 * Basically, this module selects a random challenge/response line from a file
 * (default file is /etc/security/), prompts the authenticating user with the
 * challenge string and checks their response against the expected response,
 * case-insensitive. If the response is as expected PAM_SUCCESS is returned,
 * if not PAM_AUTH_ERR is returned. Simple as that.
 *
 * The most basic example of using this module is to add a line like so to one
 * of your /etc/pam.d/ PAM config files:
 *     auth required pam_pkulcha.so [path_to_sourc_file]
 * where the source file is optional and if not supplied, DEFAULT_SRC_FILE below
 * is used.
 *
 * To specify the challenge/response pairs create/edit the source file such that
 * each line has a challenge and response which are separated by a '|'
 * character. I've used this file to specify the first and last parts of movie
 * quotes (hence the reference to 'pop culture' in the name). The source file
 * can contain comment lines (starting with the '#' character) and empty lines,
 * both of which will be ignored.
 *
 * Credits:
 *  - Roy Keene who's pam_success example, complete with automake (which I still
 *    currently know little about) formed the basis for this module. Thanks to
 *    his wiki page and pam_success module, I was able to fumble along enough
 *    to get this far. http://www.rkeene.org/projects/info/wiki/222
 *  - ShadowRanger for his answer at Stack Overflow for pulling a random line
 *   from a file using C:
 *   https://stackoverflow.com/questions/40118509/read-random-line-from-txt-file
 */

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
#include <ctype.h>

#define DEFAULT_SRC_FILE "/etc/security/pam_pkulcha.txt"

/* trims whitespace from the beginning the and end of a string
 */
char* strtrim(char *instr) {
	int i, start;
	char ch;

	/* find the index of the first non-whitespace */
	int len = (int)strlen(instr);
	for (i=0;instr[i] != '\0';i++) {
		ch = instr[i];
		if (ch == ' ' || ch == '\n' || ch == '\t' || ch == '\r')
      continue;
		/* exit with i set to the current index (which is non-whitespace or
	     the terminator of the stirng)
			 so, 'start' becomes the index of the start of the stripped string */
	  start = i;
		break;
  }

  /* from the end of the string work back and remove whitespaces by copying
	   the string terminator back */
	i = strlen(instr) - 1;
  while (1) {
		if (i < start) {
			i++;
			break;
		}

		ch = instr[i];
		if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
			instr[i--] = '\0';
			continue;
		}
		/* if we get here, we've hit a non-whitespace char so exit */
		break;
	}

	/* shift the whole string back to the start of the original buffer */
	for (i=0;i<strlen(instr);i++) {
		instr[i] = instr[start + i];
		if (instr[i] == '\0')
			break;
	}
	return instr;
}

/* tests for the strtrim() function above
void test_strstrip() {
  char ts1[100] = "  two gap   at the start and end  ";
  char ts2[100] = " one gap at the start  ";
  char ts3[100] = "no gaps";
  char ts4[100]= "";
  printf("ts1: |%s|\n", strtrim(ts1));
  printf("ts2: |%s|\n", strtrim(ts2));
  printf("ts3: |%s|\n", strtrim(ts3));
  printf("ts4: |%s|\n", strtrim(ts4));
} */

/* returns a random line from a file.
   Empty lines, whitespace-only lines and comment lines where the first
	 non-whitespace char is '#' are all skipped.
 */
char* random_line_from_file(const char* filename) {
	/* shamelessly taken from the elegant answer at:
	   https://stackoverflow.com/questions/40118509/read-random-line-from-txt-file
	 */
	FILE *f;
	size_t lineno = 0;
	size_t selectlen;
	/* buffer sizes are enough to contain the challenge and the response
	   plus some whitespace */
	char selected[PAM_MAX_MSG_SIZE + PAM_MAX_RESP_SIZE + 100];
	char current[PAM_MAX_MSG_SIZE + PAM_MAX_RESP_SIZE + 100];
	selected[0] = '\0'; /* Don't crash if file is empty */
	double rnd;

  srand(time(NULL));

	f = fopen(filename, "r"); /* Add your own error checking */
	while (fgets(current, sizeof(current), f)) {
		  /* skip the line if it's empty or starts with a comment */
		  strtrim(current);
			if (current[0] == '\0' || current[0] == '#')
				continue;

		  rnd = (double)rand()/RAND_MAX;
			if (rnd < (1.0 / (double)(++lineno))) {
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


/* Copies the '|' separated challenge and response 'line' into the
   'challenge' and 'response' buffers
 */
int get_chal_resp_from_line(char *line, char *challenge, char *response) {
  char *token, *p;
  token = strtok_r(line, "|", &p);
  strcpy(challenge, (token == NULL ? "" : token));

  token = strtok_r(NULL, "|", &p);
  strcpy(response, (token == NULL ? "" : token));

  strtrim(challenge);
  strtrim(response);

  return 1;
}

/* pull a random line from the specified file and copy the '|' separated
   challenge and response into the provided buffers
 */
int get_chal_resp(char *filename, char *challenge, char *response) {
  char *chalresp = random_line_from_file(filename);
  get_chal_resp_from_line(chalresp, challenge, response);

  free(chalresp);
  return 0;
}

/* convert a string to lower case
 */
char* lower(char *p) {
  char *orig = p;
  for ( ; *p; p++) *p = tolower(*p);
  return orig;
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
  char challenge[PAM_MAX_MSG_SIZE];
  char response[PAM_MAX_MSG_SIZE];

  /* set the file if it's specified, otherwise use the default */
  if (argc < 1) {
    strcpy(srcFile, DEFAULT_SRC_FILE);
  }
  else {
    strcpy(srcFile, argv[0]);
  }
  pam_syslog(pamh, LOG_INFO, "srcFile: %s\n", srcFile);

  /* obtain a random challenge/response from the source file */
  get_chal_resp(srcFile, challenge, response);
	/* convert the expected response to lower case */
  lower(response);

  /* set the prompt to be the challenge string and allocate a response
	   variable */
  struct pam_message msg = { .msg_style = PAM_PROMPT_ECHO_ON,
                             .msg = strcat(challenge, ": ") };
  struct pam_message *ptr_msg = &msg;
  const struct pam_message *msgs[1] = {ptr_msg};
	struct pam_response *resps = NULL;

  /* obtain the application's conversation function and call it */
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval == PAM_SUCCESS) {
    retval = conv->conv(1, msgs, &resps, conv->appdata_ptr);
  }

  /* if the conversation function was not successful */
  if (retval != PAM_SUCCESS || resps == NULL || resps->resp == NULL ) {
    /* conversation failed */
    pam_syslog(pamh, LOG_ERR, "PAM conversation failed.");
    return(PAM_AUTH_ERR);
  }

  /* convert the conversation response to lower case, and prepare the
	   success/fail auth value depending on the response */
  strtrim(lower(resps->resp));
  retval = (strcmp(response, resps->resp) == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;

  /* clean up and return the appropriate value for the given response */
  free(resps);
  return(retval);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_IGNORE);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_IGNORE);
}
