#include <gmp.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "domain_parameters.h"
#include "point.h"
#include "curves.h"
#include "benchmark.h"
#include "signature.h"

/*Run a benchmark with different curve parameters and print CSV result to out
 *Comma-Separated Values (CSV), RFC 4180: http://tools.ietf.org/html/rfc4180 */
void benchmark(FILE* out, int i)
{
	//Print CSV header
	fprintf(out, "Curve, Public key generation time, Signature generation time, Signature verification time, Operation time\r\n");

	//If the illiterator is invalid use default illiterator
	if(i < 1)
		i = DEFAULT_TEST_ILLITERATOR;	

	//Loop through all curves, since we're benchmarking them towards eachother.
	int curve_i;
	for(curve_i = 0;curve_i < NUMBER_OF_CURVES;curve_i++)
	{
		//Set initial timer
		clock_t start = clock();

		int test_i;

		//Load curve
		domain_parameters curve = domain_parameters_init();
		domain_parameters_load_curve(curve, curve_i);

		//Print curve name
		fprintf(out, "%s, ", curve->name);

		//Get a private key
		mpz_t d;mpz_init(d);
		mpz_sub_ui(d, curve->n, 2);	//Private key must be between 1 and n-1

		//Get a message to sign
		mpz_t m;mpz_init(m);
		mpz_sub_ui(m, curve->n, 2);	//Must be between 1 and n-1
		//NOTE: I assume we're using a hash algorithm giving result with the biggest bit-length possible

		//Initialize a signature
		signature sig = signature_init();

		//Initialize public key
		point Q = point_init();

		//Save time at the start of public key generation
		clock_t start_gen_Q = clock();

		//Generate public key
		for(test_i = 0; test_i < i; test_i++)		
			signature_generate_key(Q, d, curve);

		//Save time between public key generation and signature generation
		clock_t start_sign = clock();

		//Generate signature
		for(test_i = 0; test_i < i; test_i++)
			signature_sign(sig, m, d, curve);

		//Save time between signature generation and signature verification
		clock_t start_verify = clock();

		//Verify signature
		bool result;
		for(test_i = 0; test_i < i; test_i++)
			result = signature_verify(m, sig, Q, curve);

		//Save time after verification
		clock_t end_verify = clock();

		//Clear variables
		mpz_clear(d);
		domain_parameters_clear(curve);
		signature_clear(sig);
		mpz_clear(m);

		//Save time before printing
		clock_t end = clock();

		//Print public key generation time
		fprintf(out, "%.4f, ", ((double) (start_sign - start_gen_Q)) / CLOCKS_PER_SEC);

		//Print signature generation time
		fprintf(out, "%.4f, ", ((double) (start_verify - start_sign)) / CLOCKS_PER_SEC);

		//Print signature verification time
		fprintf(out, "%.4f, ", ((double) (end_verify - start_verify)) / CLOCKS_PER_SEC);

		//Print operation time
		if(result)
			fprintf(out, "%.4f", ((double) (end - start)) / CLOCKS_PER_SEC);
		else
			fprintf(out, "-1");

		//print a new line
		fprintf(out, "\r\n");	//Acoording to RFC4180 this must be done with CLRF
	}
}


