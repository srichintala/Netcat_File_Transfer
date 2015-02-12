#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<math.h>
#include<unistd.h>
#include<string.h>
#include<netdb.h>
#include<stdlib.h>
#include<openssl/hmac.h>

#define H_SIZE EVP_MAX_MD_SIZE

static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

typedef struct nc_args{
  struct sockaddr_in destaddr; //destination/server address
  unsigned short port; //destination/listen port
  unsigned short listen; //listen flag
  int n_bytes; //number of bytes to send
  int offset; //file offset
  int verbose; //verbose output info
  int message_mode; // retrieve input to send via command line
  char * message; // if message_mode is activated, this will store the message
  char * filename; //input/output file
}nc_args_t;

void usage(FILE * file){
  fprintf(file,
         "netcat_part [OPTIONS]  dest_ip [file] \n"
         "\t -h           \t\t Print this help screen\n"
         "\t -v           \t\t Verbose output\n"
	 "\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
	 "                \t\t Warning: if you specify this option, you do not specify a file. \n"
         "\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
         "\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
         "\t -o offset    \t\t Offset into file to start sending\n"
         "\t -l           \t\t Listen on port instead of connecting and write output to file\n"
         "                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
         );
}

/**
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 **/
void parse_args(nc_args_t * nc_args, int argc, char * argv[]){
  int ch;
  struct hostent * hostinfo;
  //set defaults
  nc_args->n_bytes = 0;
  nc_args->offset = 0;
  nc_args->listen = 0;
  nc_args->port = 6504;
  nc_args->verbose = 0;
  nc_args->message_mode = 0;
 
  while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) {
    switch (ch) {
    case 'h': //help
      usage(stdout);
      exit(0);
      break;
    case 'l': //listen
      nc_args->listen = 1;
      break;
    case 'p': //port
      nc_args->port = atoi(optarg);
      break;
    case 'o'://offset
      nc_args->offset = atoi(optarg);
      break;
    case 'n'://bytes
      nc_args->n_bytes = atoi(optarg);
      break;
    case 'v':
      nc_args->verbose = 1;
      break;
    case 'm':
      nc_args->message_mode = 1;
      nc_args->message = malloc(strlen(optarg)+1);
      strncpy(nc_args->message, optarg, strlen(optarg)+1);
      break;
    default:
      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      usage(stdout);
      exit(1);
    }
  }
 
  argc -= optind;
  argv += optind;
 
  if (argc < 2 && nc_args->message_mode == 0){
    fprintf(stderr, "ERROR: Require ip and file\n");
    usage(stderr);
    exit(1);
  } else if (argc != 1 && nc_args->message_mode == 1) {
    fprintf(stderr, "ERROR: Require ip send/recv from when in message mode\n");
    usage(stderr);
    exit(1);
  }
 
  if(!(hostinfo = gethostbyname(argv[0]))){
    fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
    usage(stderr);
    exit(1);
  }

  nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  bcopy((char *) hostinfo->h_addr,
        (char *) &(nc_args->destaddr.sin_addr.s_addr),
        hostinfo->h_length);
   
  nc_args->destaddr.sin_port = htons(nc_args->port);
   
  /* Save file name if not in message mode */
  if (nc_args->message_mode == 0) {
    nc_args->filename = malloc(strlen(argv[1])+1);
    strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);
	
	
  }
  return;
}

void splitStrings(char *str, char *macRecv, char *msgRecv)
{
	int i,j=1;
	char delim = '#',ch=' ';
	char hashlen[2];
	
	memset(hashlen,0,sizeof(hashlen));
	memset(msgRecv,0,sizeof(msgRecv));
	memset(macRecv,0,sizeof(macRecv));
	int len = strlen(str);
	
	for(i = len -1;i>=0 ;i--,j--)
	{
			
		if(str[i] == delim)
		{
			break;
		}
		hashlen[j] = str[i];
	}
	
	int hl= atoi(hashlen);
	
	int msglen = len - hl - 3; // -3 for delimiting char # and 2 digit hash length 
	
	char msg[msglen];
	memset(msg,0,sizeof(msg));
	for(i=0;i<msglen;i++)
	{
		msg[i] = str[i];
	}
	strcpy(msgRecv,msg);
	for(i=msglen,j=0;i<msglen+hl;i++,j++)
	{
		
		macRecv[j]=str[i];
	}
	
}
char * readFileIntoBuffer(char *macRecv,char *filename)
{
	FILE *fp;
	int fileSize,hashlen;
	fp = fopen(filename,"r");
	char *completeFile,buffer[1024];
	fseek(fp,0L,SEEK_END);
	fileSize = ftell(fp);
        int k=0;
	completeFile = malloc(sizeof(char)*fileSize);
	memset(completeFile,0,sizeof(completeFile));
	rewind(fp);
	while(fread(buffer,1,1024,fp))
	{	
		strcat(completeFile,buffer);
		memset(buffer,0,sizeof(buffer));
	}
	char * fileData = malloc(sizeof(char)*fileSize);
	memset(fileData,0,sizeof(fileData));
	
	splitStrings(completeFile,macRecv,fileData);
	
	printf("\n extracted the Message, MAC and the hash length");
	fclose(fp);
	return fileData;
}
int main(int argc, char * argv[])
{
	int sock_serv, sock_cli;
	struct sockaddr_in server,client;
	nc_args_t nc_args;
	

	int size;
	char str[1024],hash[H_SIZE],macRecv[H_SIZE];
	FILE *fp;
	
	parse_args(&nc_args, argc, argv);
	
	sock_serv=socket(AF_INET, SOCK_STREAM, 0);
	
	if(bind(sock_serv, (struct sockaddr*)&(nc_args.destaddr), sizeof(nc_args.destaddr))<0)
	{
		printf("\n port address is already bind\n");
		return 0;
	}
	if(nc_args.verbose == 1)
		printf("Server is bind successfully");
	listen(sock_serv, 5);
	if(nc_args.verbose == 1)
			printf("Server is listening");
	size= sizeof(struct sockaddr);
	sock_cli= accept(sock_serv, (struct sockaddr*)&client,(socklen_t*)&size);
	printf("Connected to client successfully");
	fp = fopen(nc_args.filename,"w");
	if(nc_args.verbose == 1)
			printf("\nFile opened");
	memset(str,0,sizeof(str));
	while(read(sock_cli,str,1024))
	{
		fwrite(str,1,strlen(str),fp);
		if(nc_args.verbose == 1)
			printf("\nin main reading from client\n\nthe total string received is = %s\nlength of str =%d",str,strlen(str));
		memset(str,0,sizeof(str));	
	}
	
	printf("\nReceived the file");
	fclose(fp); 
	char *filedata = NULL;
	filedata = readFileIntoBuffer(macRecv,nc_args.filename);
	if(nc_args.verbose == 1)
		printf("\n\nin main\n\nmacRecv = %s",macRecv);
	
	unsigned char *mac = (unsigned char *)malloc(H_SIZE);
	mac = HMAC(EVP_sha1(),key,sizeof(key)-1,(unsigned char *)filedata,sizeof(filedata)-1,NULL,NULL);
	if(nc_args.verbose == 1)
		printf("\nthis is mac Compute %s",mac);
	if(strcmp(mac,macRecv)==0)
		printf("\n Message Authentic");
	close(sock_cli);
	close(sock_serv);
}

