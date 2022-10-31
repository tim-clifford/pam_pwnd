/*
 * pwn_chk.c - Test an SHA1 hash against the HaveIBeenPwnd API.
 *
 * Steve
 *
 */


#define _XOPEN_SOURCE 700 /* For getline() */

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <ctype.h>

/*
 * Test to see if the given SHA1-hash is known to the HaveIBeenPwnd site.
 * Expects uppercase hash.
 *
 * Return value:
 *
 * <0:  Error performing the test.
 *  0:  No leak.
 * >0:  Leaked.
 *
 */
int was_leaked(char *hash)
{

	/*
	 * Sanity-check that our input is valid.
	 */
	if (hash == NULL  || strlen(hash) != 40)
	{
		openlog("pam_pwnd", 0, 0);
		syslog(LOG_ERR, "pam_pwnd: Invalid input for was_leaked(%s).", hash);
		closelog();
		return -1;
	}

	FILE* file_descriptor = fopen("/etc/pwned-passwords.txt", "r");
	if (file_descriptor == NULL) {
		return -1;
	}

	size_t line_size = 41;
	char* line = malloc(line_size*sizeof(char)); // it will get realloced longer
	char pwned_hash[41] = {'\0'};

	int return_val = 0;

	while (1) {
		if (getline(&line, &line_size, file_descriptor) == -1) {
			// check errno and maybe return -1?
			break; // fail open, but also if we reach the end of the file
		}

		strncpy(pwned_hash, line, 40);
		if (strcmp(pwned_hash, hash) == 0) {
			return_val = 1;
			break;
		}
	}

	fclose(file_descriptor);
	free(line);

	return return_val;
}
