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

/* trims whitespace from the beginning the and end of a string
 */
int strtrim(char *instr) {
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
	return 1;
}
/* tests for the strtrim() function above
void test_strstrip() {
  char ts1[100];
  char ts2[100];
  char ts3[100];
  char ts4[100];
  strcpy(ts1, "  two gap   at the start and end  ");
  strcpy(ts2, " one gap at the start  ");
  strcpy(ts3, "no gap");
  strcpy(ts4, "");
  strtrim(ts1);
  strtrim(ts2);
  strtrim(ts3);
  strtrim(ts4);
  printf("ts1: |%s|\n", ts1);
  printf("ts2: |%s|\n", ts2);
  printf("ts3: |%s|\n", ts3);
  printf("ts4: |%s|\n", ts4);
} */

/* returns a random line from a file.
   Empty lines, whitespace-only lines and comment lines where the first
	 non-whitespace char is '#' are all skipped.
 */
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
		  /* skip the line if it's empty or starts with a comment */
		  strtrim(current);
			if (current[0] == '\0' || current[0] == '#')
				continue;

		  rnd = (double)rand()/RAND_MAX;
			if (rnd < (1.0 / (double)(++lineno))) {
				  /* printf("########## if condition met. rnd %.03f line %d\n", rnd, (int)lineno);
					 */
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
  char challenge[512];
  char response[512];

  /* set the file if it's specified, otherwise use the default */
  if (argc < 2) {
    strcpy(srcFile, "/etc/security/pam_pkulcha.txt");
  }
  else {
    strcpy(srcFile, argv[1]);
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
