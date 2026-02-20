#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <crypt.h>
#include <sys/time.h>
#include <pthread.h>


#define OPTIONS "i:p:o:nt:vh"
#define MICROSECONDS_PER_SECOND 1000000.0
char** read_file(char *, int*);
void compare_and_concrypt(char **, char**, int, int, int, FILE *);
int crack_one_hash(char*, char**, int, FILE*);
void* twork(void* tdata);

struct worker_args {
	long tid;
	struct thread_data *shared;
};
struct thread_data{
	char** hash_array;
	char** password_array;
	int password_count;
	int total_hashes;
	int next_indx;
	pthread_mutex_t lock;
	FILE* output;
};

void* twork(void* tdata){
	struct worker_args *args = tdata;
	struct thread_data *shared = args->shared;
	struct timeval start;
	struct timeval end;
	double elapsed_time =0;
	int num_cracked= 0;
	int failed_cracked =0;
	int curr_indx=0;
	gettimeofday(&start, NULL);
	while(1){
		pthread_mutex_lock(&shared->lock);
		if(shared->next_indx >= shared->total_hashes){
			pthread_mutex_unlock(&shared->lock);
			break;
		}
		curr_indx = shared->next_indx;
		shared->next_indx++;
		pthread_mutex_unlock(&shared->lock);
		if(crack_one_hash(shared->hash_array[curr_indx], shared->password_array, shared->password_count, shared->output) == 1){
			++num_cracked;
		}
		else{
			++failed_cracked;
		}

	}
	gettimeofday(&end, NULL);
	elapsed_time = (((double) (end.tv_usec - start.tv_usec))
			/MICROSECONDS_PER_SECOND) 
		+((double) (end.tv_sec - start.tv_sec));
	fprintf(stderr, "thread: %ld, %.2f, sec cracked: %d, failed: %d total: %d\n", args->tid, elapsed_time, num_cracked, failed_cracked, num_cracked+failed_cracked);
	return NULL;

}	



int crack_one_hash(char* hash, char** password_arr, int passw_count, FILE* out){
	const char * salt_val = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	char * result;
	char * password;
	char salt[3] = {0};
	bool found = false;
	for(int s1 = 0; s1 < 64 && !found; s1++){
		for(int s2 = 0; s2 < 64 && !found; s2++){
			salt[0] = salt_val[s1];
			salt[1] = salt_val[s2];
			salt[2] = '\0';
			for(int k = 0; k < passw_count; ++k){
				struct crypt_data data;
				memset(&data, 0, sizeof(data));
				password = password_arr[k];
				result = crypt_rn(password, salt, &data, sizeof(data));
				if(strcmp(hash, result +2) == 0){
					found = true;
					fprintf(out,"cracked: %s : %s\n", hash, password);
					return 1;
				}

			}
		}
	}
	if(!found){
		fprintf(out,"*** failed: %s\n", hash);
	}
	return 0;
}


void compare_and_concrypt(char ** inpt_arr, char** pass_arr, int pass_count, int i_count, int num_threads, FILE* output){
		
	struct thread_data shared_data;
	long tid =0;
	pthread_t *threads = NULL;
	struct worker_args *worker_data = NULL;
	shared_data.hash_array = inpt_arr;
	shared_data.password_array = pass_arr;
	shared_data.total_hashes = i_count;
	shared_data.password_count = pass_count;
	shared_data.next_indx = 0;
	shared_data.output = output;

	threads = malloc(num_threads *sizeof(pthread_t));
	worker_data = malloc(num_threads *sizeof(struct worker_args));
	pthread_mutex_init(&shared_data.lock, NULL);

	for(tid=0; tid < num_threads; tid++){
		worker_data[tid].shared = &shared_data;
		worker_data[tid].tid = tid;
		pthread_create(&threads[tid], NULL, twork, &worker_data[tid]);
	}
	for(tid =0; tid < num_threads; tid++){
		pthread_join(threads[tid], NULL);
	}

	pthread_mutex_destroy(&shared_data.lock);

	free(threads);
	free(worker_data);
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
				nice(10);
				break;
			case 't':
				threadcnt = atoi(optarg);
				break;
			case 'v':
				is_verbose = true;
				break;
			case 'h':
				printf("help text\n");
				printf("\tdesplodocus_mt ...\n");
				printf("\tOptions: i:o:p:t:nvh\n");
				printf("\t\t-i file\t\thash file name (required)\n");
				printf("\t\t-p file\t\tplain word file name (required)\n");
				printf("\t\t-o file\t\toutput file name (default stdout)\n");
				printf("\t\t-t #\t\tnumber of threads to create (default 1)\n");
				printf("\t\t-n\t\tbe nice\n");
				printf("\t\t-v\t\tenable verbose mode\n");
				printf("\t\t-h\t\thelpful text\n");
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

	if(threadcnt <= 0) {threadcnt = 1;}

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
	compare_and_concrypt(ifile_arr, pfile_arr, pcount, icount, threadcnt, out);


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
