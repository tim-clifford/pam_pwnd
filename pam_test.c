/*
 * pam_test.c : Simple test-cases to exercise our code at least a little.
 */


#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sha1.h"

/*
 * The lookup of the password is handled via this external function.
 */
extern int was_leaked(char *hash);


/*
 * This structure describes a simple SHA1-test.
 *
 * We provide an input and ensure that the output hash matches
 * the given output.
 */
typedef struct sha1_test_case
{
	/*
	 * Input to the test-case.
	 */
	char *input;

	/*
	 * Expected output.
	 */
	char *output;

} sha1_test_case;


/*
 * This structure describes a simple API-lookup -test.
 *
 * We provide an input and ensure that the output result matches.
 */
typedef struct pwn_test_case
{
	/*
	 * Input to the test-case.
	 */
	char *input;

	/*
	 * Expected result
	 */
	int result;

} pwn_test_case;


/*
 * Test that our SHA1-implementation returns somewhat reasonable
 * results.
 */
void test_sha1()
{

	/*
	 * Our test-cases - contain the expected input and output
	 */
	sha1_test_case input[]  =
	{
		{ "steve", "9CE5770B3BB4B2A1D59BE2D97E34379CD192299F"},
		{ "ssh.pass", "F9ECF6396E3B442DF3DAE72B81FEC784D2B2900D" },
		{ "ssh.pasS", "276ED889F7D9A00E24DB1C07579F5B78F19BA204"},
		{ "x", "11F6AD8EC52A2984ABAAFD7C3B516503785C2072"},
		{ "xx", "DD7B7B74EA160E049DD128478E074CE47254BDE8"},
		{ "password", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"},
		{ "secret", "E5E9FA1BA31ECD1AE84F75CAAA474F3A663F05F4" },
		{ "25121974", "137BABE83F739E3B71211F422FE4C6850F322279"},
	};

	/*
	 * For each case.
	 */
	size_t cases = sizeof(input) / sizeof(input[0]);

	for (size_t i = 0; i < cases; i++)
	{

		/*
		 * Calculate the SHA1-hash of the input, and ensure
		 * it matches the expected value.
		 */
		unsigned char hash[20];
		SHA1_CTX ctx;
		SHA1Init(&ctx);
		SHA1Update(&ctx, (unsigned char*)input[i].input, strlen(input[i].input));
		SHA1Final(hash, &ctx);

		/*
		 * Convert the output to a readable-value.
		 */
		char result[41] = {'\0'};

		for (int i = 0; i < 20; i++)
			sprintf((char*)result+2*i, "%02X", hash[i]);


		if (strcmp(input[i].output, result) != 0)
		{
			printf("%zu - FAIL: Test input '%s' gave hash '%s' not '%s'\n",
				   i + 1, input[i].input, result, input[i].output);
			exit(1);
		}
		else
		{
			printf("%zu - OK: Test input '%s' gave expected hash '%s'\n",
				   i + 1, input[i].input, input[i].output);
		}
	}
}


/*
 * Test that the lookup against the remote API looks somewhat sane.
 *
 */
void test_pwn_lookup()
{
	/*
	 * Plain-text passwords to lookup, and expected result.
	 */
	pwn_test_case input[]  =
	{

		/* Listed in the DB*/
		{ "hmm", 1},
		/*{ "steve", 1},*/
		/*{ "secret", 1},*/
		/*{ "secure", 1},*/
		/*{ "CorrectHorseBatteryStaple", 1},*/

		/*[> Not listed in the DB <]*/
		{ "fodspfsdpfksdlfdfjlsdfjldfj", 0 },
		{ "fdkslf930290kqldsdsfs", 0 },
		{ "290809lkfddks,lfdfsdfdsfdsf-_FD-f0s-f09d-0f9sdf0-9q3q12", 0 },
	};

	/*
	 * For each case.
	 */
	size_t cases = sizeof(input) / sizeof(input[0]);

	for (size_t i = 0; i < cases; i++)
	{

		/*
		 * Calculate the SHA1-hash of the input.
		 */
		unsigned char hash[20];
		SHA1_CTX ctx;
		SHA1Init(&ctx);
		SHA1Update(&ctx, (unsigned char*)input[i].input, strlen(input[i].input));
		SHA1Final(hash, &ctx);

		/*
		 * Convert the output to a readable-value.
		 */
		char result[41] = {'\0'};

		for (int i = 0; i < 20; i++)
			sprintf((char*)result+2*i, "%02X", hash[i]);


		/*
		 * Now lookup that hash.
		 */
		int found = was_leaked(result);

		if (found != input[i].result)
		{
			printf("%zu - FAIL: Test input '%s' gave '%d' not '%d'\n",
				   i + 1, input[i].input, found, input[i].result);
			exit(1);
		}
		else
		{
			printf("%zu - OK: Test input '%s' gave expected result.\n",
				   i + 1, input[i].input);
		}
	}
}



/*
 * Entry-Point.
 */
int main(int argc, char *argv[])
{

	/*
	 * Test hash.
	 */
	test_sha1();

	/*
	 * Test Pwnage.
	 */
	test_pwn_lookup();


	exit(0);
}
