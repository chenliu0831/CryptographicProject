#ifndef _COMMON_XCRYPT
#define _COMMON_XCRYPT


#define __NR_xcrypt 349
#define EXTRA_CREDIT 

struct xcrypt_args {
        char  *infile; 
        char  *outfile;
       	void  *keybuf; /* -p */
	size_t keylen; /* -l*/
	int flags;  /* -e -d*/
	#ifdef EXTRA_CREDIT
	int blk_size;  /*-u*/
	char *cipher_alg; /**/
	
        #endif
};





#endif
