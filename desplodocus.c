#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>

#define OPTIONS "i:p:o:nt:vh"

int main(int argc, char*argv[]){
	int opt = 0;
	char * ifile = NULL;
	char * pfile = NULL;
	char * ofile = NULL;
	int threadcnt = 1;
	bool is_verbose = false;
	while((opt = getopt(argc, argv, OPTIONS)) != -1){
		switch(opt){
			case 'i':
				ifile = optarg;
				break;
			case 'p':
				pfile = optarg;
				break;
			case 'o':
				ofile = optarg;
				break;
			case 'n':
				break;
			case 't':
				break;
			case 'v':
				is_verbose = true;
				break;
			case 'h':
				printf("-i: specify name of the input file that DES hashes.\n"
						"-p: specify name of input file of plaintext passwords\n"
						"-o: specify name of output file, if none given output goes to stdout\n"
						"-t: number of threads to use\n"
						"-v: enable verbose logging\n"
						"-h: help\n");
				exit(EXIT_SUCCESS);
				break;
			default:
				fprintf(stderr,"Invalid option, please select valid flag\n");
				exit(EXIT_FAILURE);
				break;
		}
	}

	exit(EXIT_SUCCESS);
}
