#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <errno.h>
#include "manage_key.h"

static const char *optString = ":s:h";

int revoke_key(char *key,size_t len)
{
	int i =0;
	while(i<len){
		
		if(key[i] != '0'){
		       
			return 0; 
		}
		i++;
	   	
	}
	
	return 1;
}
int main(int argc, char **argv)
{

	int fd = -1;
	long res= 0;
	int res_ssl =0;
        
	
	/*For openssl use*/
	char *salt = "testtestetsetstsetset";
	size_t salt_len = strlen(salt);
	int iter = 10000;

	
	int opt =0;
	int errflag =0;
	int sflag =0;
       

	int sys_keylen = 32;
	char *user_key = NULL;
        size_t user_key_len =0;
	char *file_name;
	char *sys_key;
	extern char *optarg;
	extern int optind,optopt;
	
       	while((opt = getopt(argc,argv,optString))!=-1){
		switch(opt){
		case 's':
			sflag ++;
			user_key = optarg;
			break;
		case 'h':
			printf("Usage: manage_key -s passphrase");
			break;

		case ':':
		        fprintf(stderr,"Option -%c needs parameter\n",
				optopt);
			errflag++;
			break;
	      	case '?':
			fprintf(stderr,"Unknown option: -%c\n",optopt);
		        errflag++;
		default:
			break;
		}
	}
		
		if(!sflag){
			fprintf(stderr, "No key input!\n");
			exit(2);
		}		
	      
		if(errflag){
			fprintf(stderr, "Err in argument. Usage: manage_key -s key");
			exit(2);
		}
		if(optind != argc-1){
		     
			printf("Argument number error!!\n");
			exit(2);
		}
		file_name = argv[optind];
		
		if((fd = open(file_name,O_RDWR)) < 0){
			fprintf(stderr,"File open failure!\n");
		        return -1;
		}
		
		if(user_key)
			user_key_len = strlen(user_key);
		else 
			return -1;

	       
		if(revoke_key(user_key,user_key_len)){
			printf("Using ioctl to revoke key\n");
			res = ioctl(fd,WRAPFS_REVOKE_KEY);
			if(res <0){
				fprintf(stderr,
					"Key are not revoked, return %ld\n",
					res);
			}
			return res;
		}
		sys_key = (char*)malloc(sys_keylen);
		memset(sys_key,0,sys_keylen);

		res_ssl = PKCS5_PBKDF2_HMAC_SHA1((const char *)(user_key),
						 user_key_len,(unsigned char *) salt,
						 salt_len,iter,sys_keylen,
						 (unsigned char*)sys_key);
		if(res_ssl<=0){
			printf("key generation error!\n");
			free(sys_key);
			return res_ssl;
		}

		printf("Setting key to wrapfs\n");
		if((res = ioctl(fd,WRAPFS_SET_KEY,sys_key)) < 0){
			fprintf(stderr, "WRAPFS SET KEY Error, return %ld\n",res);
			free(sys_key);
			return res;
		}
		printf("Finish Setting Key\n");
		
		if(sys_key)
			free(sys_key);

		return 0;
}
