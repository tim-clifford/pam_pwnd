/*
 * pam_pwnd.c - Test password against the Have I Been Pwnd list.
 *
 * Steve, modified by tc565
 *
 */

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>

#include "sha1.h"

/*
 * The lookup of the password is handled via this external function.
 */
extern int was_leaked(char* hash);

// tc565: perhaps too much code is copied between pam_sm_chauthtok and
// pam_sm_authenticate
//
int check_password(pam_handle_t* pamh, const char** userName) {

	const char* userPasswd = NULL;
	/*
	 * Get the username.
	 */
	if (pam_get_user(pamh, userName, NULL) != PAM_SUCCESS)
	{
		openlog("pam_pwnd", 0, 0);
		syslog(LOG_ERR, "pam_pwnd: cannot determine user name.");
		closelog();
		return -1;
	}

	/*
	 * Get the password.
	 */
	if (pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&userPasswd, NULL) !=
			PAM_SUCCESS)
	{
		openlog("pam_pwnd", 0, 0);
		syslog(LOG_ERR, "pam_pwnd: error getting user password.");
		closelog();
		return -1;
	}

	/*
	 * Sanity-Check
	 */
	if (*userName == NULL || userPasswd == NULL)
	{
		openlog("pam_pwnd", 0, 0);
		syslog(LOG_ERR, "pam_pwnd: cowardly aborting due to null pointer(s).");
		closelog();
		return -1;
	}

	/*
	 * (SHA1) Hash the password.
	 */
	unsigned char hash[20];
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, (unsigned char*)userPasswd, strlen(userPasswd));
	SHA1Final(hash, &ctx);

	/*
	 * Convert to a hex-string.
	 */
	char buf[41] = {'\0'};

	/*
	 * NOTE: We upper-case the string here, but we also repeat that
	 * later on. Just because.
	 */
	for (int i = 0; i < 20; i++)
		sprintf((char*)buf+2*i, "%02X", hash[i]);

	/*
	 * Lookup the hash
	 */
	return was_leaked(buf);
}

// This function is called when an attempt to change the password occurs.
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char* userName = NULL;

	int pwnd_state = check_password(pamh, &userName);

	// Handle the result.
	if (pwnd_state < 0) {
		/*
		 * If the return value is <0 that means that something failed.
		 *
		 * We could deny the login here, but it is better to fail open.
		 */
		openlog("pam_pwnd", 0, 0);
		syslog(LOG_ERR, "pam_pwnd: couldn't perform hash-test for %s properly.", userName);
		closelog();
		return PAM_SUCCESS;
	} else if (pwnd_state == 0) {
		// No result :)
		return PAM_SUCCESS;
	} else {
		// l33t hax0rs have already stolen your password.
		printf("This password is in our list of pwned passwords. Please choose another.\n");
		return PAM_PERM_DENIED;
	}
}

// This function is called to handle authentication.
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char** argv)
{
	const char* userName = NULL;

	// Lookup the hash
	int pwnd_state = check_password(pamh, &userName);

	// Handle the result.
	if (pwnd_state < 0) {
		/*
		 * If the return value is <0 that means that something failed.
		 *
		 * We could deny the login here, but it is better to fail open.
		 */
		openlog("pam_pwnd", 0, 0);
		syslog(LOG_ERR, "pam_pwnd: couldn't perform hash-test for user %s properly.", userName);
		closelog();
	} else if (pwnd_state == 0) {
		// No result :)
	} else {
		// l33t hax0rs have already stolen your password.
		printf("WARNING: Your password is in our list of pwned passwords. Please change it ASAP.\n");
		openlog("pam_pwnd", 0, 0);
		syslog(LOG_ERR, "pam_pwnd: user %s has a pwned password!", userName);
		closelog();
	}

	return PAM_SUCCESS; // never block login
}


/*
 * Not sure why this is required, if it even is!
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char
                              *argv[])
{
	return (PAM_SUCCESS);
}
