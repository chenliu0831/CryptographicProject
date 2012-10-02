#include "user_acl.h"

void print_help()
{
	printf("-u will followed by the user id\n");
	printf("-g will followed by the group id\n");
	printf("-s will followed by the session id\n");
	printf("-p will followed by the prcess id\n");
	printf("-t will followed by the time with format XX~XX\n");
	printf("-m will followed by the permission\n");
	printf("example: ./setacl -u 1 -g 2 -s 3 -p 4 -t 10-20 -m rwe 123.txt\n");
	printf("this example will set these acl value to 123.txt file\n");
}

void print_acl(struct posix_acl *user_acl)
{
	int bound = user_acl->a_count;
	int i;
	for (i = 0; i < bound; i++) {
		printf("count: %d\n", i);
		printf("e_tag: %d\n", user_acl->a_entries[i].e_tag);
		printf("e_perm: %d\n", user_acl->a_entries[i].e_perm);
		printf("e_id: %d\n", user_acl->a_entries[i].e_id);
	}
}

unsigned int parse_time(char *optarg)
{
	int x;
	char start[3];
	char end[3];
	unsigned int t_start;
	unsigned int t_end;

	x = strcspn(optarg, "~");
	if (x < 0)
		return -1;
	memcpy(start, optarg, x);
	start[2] = '\0';
	memcpy(end, optarg + (x + 1) * sizeof(char), strlen(optarg) - x);
	end[2] = '\0';

	t_start = atoi(start);
	t_end = atoi(end);
	t_start = t_start<<16;
	t_start = t_start|t_end;
	return t_start;
}

void set_perm(struct posix_acl *user_acl, char *perm)
{
	int length;
	int i;
	unsigned int p = 0;
	int bound = user_acl->a_count;

	length = strlen(perm);
	for (i = 0; i < length; i++) {
		if (perm[i] == 'r')
			p = p|ACL_READ;
		else if (perm[i] == 'w')
			p = p|ACL_WRITE;
		else if (perm[i] == 'e')
			p = p|ACL_EXECUTE;
	}

	for (i = 0; i < bound; i++)
		user_acl->a_entries[i].e_perm = p;

}

int main(int argc, char *argv[])
{
	struct posix_acl *user_acl;
	int f;
	int err;
	int uid;
	char *perm = NULL;
	int index;
	int c;
	int op = 1;
	int time;

	uid_t current_uid;
	struct stat sb;

	user_acl = malloc(sizeof(struct posix_acl));
	user_acl->a_count = 0;

	while ((c = getopt(argc, argv, "hu:g:s:p:t:m:")) != -1) {
		switch (c) {
		case 'h':
			print_help();
			op++;
			return 1;
		case 'u':
			index = user_acl->a_count;
			if (!strcmp(optarg, "o")) {
				user_acl->a_entries[index].e_tag = ACL_USER_OBJ;
				user_acl->a_entries[index].e_id =
							ACL_UNDEFINED_ID;
			} else {
				user_acl->a_entries[index].e_tag = ACL_USER;
				user_acl->a_entries[index].e_id = atoi(optarg);
			}
			user_acl->a_count = index + 1;
			op = op + 2;
			break;
		case 'g':
			index = user_acl->a_count;
			if (!strcmp(optarg, "g")) {
				user_acl->a_entries[index].e_tag =
							ACL_GROUP_OBJ;
				user_acl->a_entries[index].e_id =
							ACL_UNDEFINED_ID;
			} else {
				user_acl->a_entries[index].e_tag = ACL_GROUP;
				user_acl->a_entries[index].e_id = atoi(optarg);
			}
			user_acl->a_count = index + 1;
			op = op + 2;
			break;
		case 's':
			index = user_acl->a_count;
			user_acl->a_entries[index].e_tag = ACL_SESSION;
			user_acl->a_entries[index].e_id = atoi(optarg);
			user_acl->a_count = index + 1;
			op = op + 2;
			break;
		case 'p':
			index = user_acl->a_count;
			user_acl->a_entries[index].e_tag = ACL_PROCESS;
			user_acl->a_entries[index].e_id = atoi(optarg);
			user_acl->a_count = index + 1;
			op = op + 2;
			break;
		case 't':
			printf("check t: optarg = %s\n", optarg);
			index = user_acl->a_count;
			time = parse_time(optarg);
			if (time < 0) {
				printf("error pase time\n");
				return -1;
			}
			user_acl->a_entries[index].e_tag = ACL_TIME;
			user_acl->a_entries[index].e_id = time;
			user_acl->a_count = index + 1;
			op = op + 2;
			break;
		case 'm':
			perm = optarg;
			break;
		}
	}

	if (perm != NULL) {
		set_perm(user_acl, perm);
		op = op + 2;
	}
	print_acl(user_acl);

	current_uid = getuid();
	if (stat(argv[op], &sb) == -1) {
		printf("error get file stat");
		return -1;
	}
	if (getuid() != sb.st_uid) {
		printf("You can't set acl on this file, because you do not own this file.");
		return -1;
	}

	f = open(argv[op], O_RDWR);
	if (f < 0) {
		printf("error open file\n");
		return -1;
	}

	printf("etag: %d", user_acl->a_entries[0].e_tag);

	err = ioctl(f, ECRYPTFS_SETACL, user_acl);
	if (err < 0) {
		printf("Error set acl\n");
		return -1;
	}
	return 0;

}
