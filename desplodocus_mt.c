#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <crypt.h>
#include <time.h>

#define OPTIONS "i:p:o:nt:vh"
char** read_file(char *, int*);
void compare_and_concrypt(char **, char**, int, int, FILE *);

void compare_and_concrypt(char ** inpt_arr, char** pass_arr, int pass_count, int i_count, FILE* output){
	const char * salt_val = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	char * hash;
	char * result;
	char * password;
	char salt[3] = {0};
	for(int i = 0; i < i_count; i++){
		bool found = false;
		for(int s1 = 0; s1 < 64 && !found; s1++){
			for(int s2 = 0; s2 < 64 && !found; s2++){
				salt[0] = salt_val[s1];
				salt[1] = salt_val[s2];
				salt[2] = '\0';
				for(int k = 0; k < pass_count; ++k){
					struct crypt_data data;
					memset(&data, 0, sizeof(data));
					hash = inpt_arr[i];
					password = pass_arr[k];
					result = crypt_rn(password, salt, &data, sizeof(data));
					if(strcmp(hash, result +2) == 0){
						found = true;
						fprintf(output,"cracked: %s : %s\n", inpt_arr[i], password);
						break;
					}

				}
			}
		}
		if(!found){
			fprintf(output,"*** failed: %s\n", inpt_arr[i]);
		}
	}
}

char ** read_file(char * inp_file, int* count){
	FILE *fp; 
	int initial_cap = 64;
	char ** line_arr = NULL;
	char * buf = NULL;
	size_t buf_size = 0;
	int cap = initial_cap;
	*count = 0;

	fp = fopen(inp_file, "r");

	if(fp ==NULL){
		perror("File error");
		exit(EXIT_FAILURE);
	}

	line_arr = malloc(initial_cap * sizeof(char *));

	if(line_arr == NULL){
		perror("Malloc");
		exit(EXIT_FAILURE);
	}

	while(getline(&buf, &buf_size, fp) != -1){
		size_t len = strlen(buf);
		char * dup_str;
		if(*count == cap){
			char ** temp = NULL;
			cap = cap *2;
			temp = realloc(line_arr, cap* sizeof(char*));
			if(temp == NULL){
				perror("realloc");
				exit(EXIT_FAILURE);
			}
			line_arr = temp;
		}
		if(len > 0 && buf[len-1] == '\n'){
			buf[len-1] = '\0';
		}
		dup_str = strdup(buf);
		line_arr[*count] = dup_str;
		(*count)++;
	}
	free(buf);
	fclose(fp);
	return line_arr;
}

int main(int argc, char*argv[]){
	int opt = 0;
	int icount =0;
	int pcount =0;
	char * ifile = NULL;
	char * pfile = NULL;
	char * ofile = NULL;
	char** ifile_arr = NULL;
	char** pfile_arr = NULL;
	FILE *out = stdout;
	//int threadcnt = 1;
	//bool is_verbose = false;
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
				nice(10);
				break;
			case 't':
				//	threadcnt = atoi(optarg);
				break;
			case 'v':
				//	is_verbose = true;
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
	if(ifile == NULL || pfile == NULL){
		fprintf(stderr,"Input files must be specified\n");
		exit(EXIT_FAILURE);
	}

	//if(threadcnt <= 0) {threadcnt = 1;}

	ifile_arr = read_file(ifile, &icount);
	pfile_arr = read_file(pfile, &pcount);

	if(ofile){
		out = fopen(ofile, "w");
		if(out == NULL){
			perror("file");
			exit(EXIT_FAILURE);
		}
	}

	//try each hash in ifile and compare to the password in pfile
	compare_and_concrypt(ifile_arr, pfile_arr, pcount, icount, out);


	//freeing all allocated memory
	for(int i = 0; i < icount; i++){
		free(ifile_arr[i]);
	}
	for(int i = 0; i < pcount; i++){
		free(pfile_arr[i]);
	}
	free(ifile_arr);
	free(pfile_arr);
	if(ofile) {
		fclose(out);
	}
	exit(EXIT_SUCCESS);
}
