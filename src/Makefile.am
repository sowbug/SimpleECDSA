bin_PROGRAMS = SimpleECDSA
SimpleECDSA_SOURCES = benchmark.c domain_parameters.c numbertheory.c random.c signature.c curves.c main.c point.c sha1.c test.c benchmark.h domain_parameters.h numbertheory.h random.h signature.h curves.h point.h sha1.h test.h 
SimpleECDSA_LDFLAGS = -lgmp
dist_check_SCRIPTS = test.sh benchmark.sh
TESTS = $(dist_check_SCRIPTS)
