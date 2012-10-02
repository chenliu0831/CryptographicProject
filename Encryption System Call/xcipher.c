#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <errno.h>
#include "xcrypt_common.h"


#ifdef EXTRA_CREDIT
static const char *optString = ":edc:p:u:l:h";
#else
static const char *optString = ":edp:h";
#endif


#ifdef EXTRA_CREDIT
static char *check[] = {
	"cbc(des)", "cbc(md5)", "cbc(des3_ede)", "cbc(rot13)", "cbc(sha1)", "cbc(sha224)", "cbc(sha256)",
	"cbc(blowfish)", "cbc(twofish)", "cbc(serpent)", "cbc(sha384)", "cbc(sha512)", "cbc(md4)", "cbc(aes)",
	"cbc(cast6)", "cbc(arc4)", "cbc(michael_mic)", "cbc(deflate)", "cbc(crc32c)", "cbc(tea)", "cbc(xtea)",
	"cbc(khazad)", "cbc(wp512)", "cbc(wp384)", "cbc(wp256)", "cbc(tnepres)", "cbc(xeta)",  "cbc(fcrypt)",
	"cbc(camellia)", "cbc(seed)", "cbc(salsa20)", "cbc(rmd128)", "cbc(rmd160)", "cbc(rmd256)", "cbc(rmd320)",
	"cbc(lzo)", "cbc(cts)", "cbc(zlib)", NULL
};
#endif
void init_args(struct xcrypt_args *args)
{
	args->infile = NULL;
	args->outfile = NULL;
	args->keybuf = NULL;
	args->keylen = 16;
	args->flags = -1;
	#ifdef EXTRA_CREDIT
	args->blk_size = getpagesize();
	args->cipher_alg = "cbc(aes)";
        #endif
}

int cipher_alg_chk(char *alg_name)
{
	
	char **name = check;
	while(*name){
		if(!strcmp(*name,alg_name))
			return 0;
		name++;
	}
	printf("Cipher alg %s not supported\n",alg_name);
	return 1;
}

int main (int argc, char** argv)
{

	
	long res= 0;
	int res_ssl =0;
        
	
	/*For openssl use*/
	char *salt = "testtestetsetstsetset";
	size_t salt_len = strlen(salt);
	int iter = 10000;

	
	int opt =0;
	int errflag =0;
	int eflag =0;
	int dflag =0;
	int pflag =0;
	int sys_keylen = 16;
	int tmp_len =0 ;
	struct xcrypt_args args_in;
	char * sys_key = NULL;
	/*	struct xcrypt_args args_dec;
        */
	extern char *optarg;
	extern int optind,optopt;
	init_args(&args_in);
       
	res =0;
	while((opt = getopt(argc,argv,optString))!=-1){
		switch(opt){
		
		case 'e':
			if(dflag){
				errflag++;
			}else {
				eflag++;
				args_in.flags = 1;
			}
			break;
		case 'd':
			if(eflag){
				errflag++;
		     	} else {
				dflag++;
				args_in.flags = 0;
			}
			break;
		case 'p':
			pflag++;
			args_in.keybuf = optarg;
			break;
	       
		case 'h':
			printf("Usage Xicpher -u -l -p -c need argument, -d -e specify encryption or decryption\n");
			break;
		#ifdef EXTRA_CREDIT
		case 'c':
			errflag = cipher_alg_chk(optarg);
			if(!errflag)
				args_in.cipher_alg = optarg;
			
			break;
		case 'u':
			args_in.blk_size =atoi(optarg);
			
			break;
		case 'l':
			args_in.keylen = atoi(optarg) >> 3;
			
			break;
                #endif	
		case ':':
			fprintf(stderr,"Option -%c needs argument\n",optopt);
			errflag++;
			break;
		case '?':
			fprintf(stderr,"Unknown option: -%c\n",optopt);
		        errflag++;
		default:
			break;
	
		}
	}
	if(!pflag) {
		fprintf(stderr,"No password input! Abort!\n");
		exit(2);
	}
	if(errflag){
		fprintf(stderr,"Err in argument.Usage...\n");
		exit(2);
	}

	if(optind != argc-2){
		printf(" argument number error!!\n");
		exit(2);
	}
	args_in.infile = argv[optind++];
	args_in.outfile = argv[optind++];
        
	tmp_len = strlen((char*)args_in.keybuf);
	/*
	printf("infile is %s, outfile is %s, key is %s,keylen is %d,flags is %d\n",
	       args_in.infile,args_in.outfile,(char*)args_in.keybuf,tmp_len,args_in.flags);
	*/
	#ifdef EXTRA_CREDIT
	       sys_keylen = args_in.keylen;
	#endif
	sys_key =(char *)malloc(sys_keylen+1);
	memset(sys_key,'\0',sys_keylen+1);
	
	res_ssl = PKCS5_PBKDF2_HMAC_SHA1((const char *)(args_in.keybuf),tmp_len,(unsigned char *) salt,
				     salt_len,iter,sys_keylen,(unsigned char*)sys_key);
	if(res_ssl<=0){
		printf("key generation error!\n");
		free(sys_key);
		return res_ssl;
	}
	args_in.keybuf = sys_key;
	args_in.keylen = sys_keylen;
	/*
	printf("new key is %s\n,new sys_keylen is %d,cipher we use is %s",(char*)args_in.keybuf,
	       args_in.keylen,args_in.cipher_alg);
       
	*/
	
		
	res = syscall(__NR_xcrypt,&args_in);

	
	if(!res){
		if(args_in.flags & 0x01)
			printf("Success executing new syscall my_sys_xcrypt for encrypting\n");
		else
			printf("Success executing new syscall my_sys_xcrypt for decrypting\n");
	} else {
		res = -errno;
		if(args_in.flags & 0x01)
			printf("Encrypting fail! return %ld\n",res);
		else
			printf("Decrypting fail! return %ld\n",res);

		switch(res){
		case -ENOMEM:
			printf("Not Enough Kernel memory!\n");
			break;
		case -EFAULT:
			printf("Bad user space address encountered!\n");
			break;
		case -ENOENT:
			printf("Input file not exist or cannot be open!\n");
			break;
		case -EINVAL:
			printf("Input file and output file are the same!\n");
			break;
		case -EPERM:
			printf("Input file underlying file system doesn't allow read\n");
			break;
		case -EROFS:
			printf("File system is a read-only FS!\n");
			break;
		case -EKEYREJECTED:
			printf("Invalid key for decryption!\n");
			break;
		case -ENODATA:
			printf("Zero size input file!\n");
			break;
		case -EIO:
			printf("file IO exception!\n");
		        break;
		case -EMEDIUMTYPE:
			printf("Decryption failure due to bad padding! File may be corrupted\n");
			break;
		case -EFBIG:
			printf("Decrypted file size is different from the original file size!\n");
			break;
		case -EUCLEAN:
			printf("Partial file cleanup failure! Please reboot and remove manually!\n");
			break;
		case -EISDIR:
			printf("Input file is not regular!\n");
			break;
		default:
			printf("Unhandled error type!\n");
			break;
		}

	}
	
        
	
	free(sys_key);
	return 0;
}
