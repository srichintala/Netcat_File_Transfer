#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/hmac.h> // need to add -lssl to compile

#define BUF_SIZE 1024
#define H_SIZE EVP_MAX_MD_SIZE

/** Warning: This is a very weak supplied shared key...as a result it is not
 * really something you'd ever want to use again :)
 */
static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

/**
 * Structure to hold all relevant state
 **/
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


/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 */
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
int connectToServer(nc_args_t * nc_args)
{
	int csocket;
	csocket = socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in client = nc_args->destaddr;
	if(connect(csocket,(struct sockaddr*)&client,sizeof(client))<0){
		printf("\nerror in socket connection");
		return -1;
	}
	printf("\nYou have connected to server");
	return csocket;
}
void closeConnection(int csocket)
{
	printf("\nclosing connection with server");
	close(csocket);
}

//Below parameters are set just in case where the file size huge and a large dynamic buffer is required.
//however, does not significantly affect the working of program.
void setMemoryAllocationParameters()
{
	mallopt(M_CHECK_ACTION,0);	// To deal with the glibc errors 	

}

void sendMsg(nc_args_t * nc_args,int csocket)
{
	
	int msglen = strlen(nc_args->message);
	char *msg;
	unsigned char *mac = (unsigned char *)malloc(H_SIZE);
	msg = malloc(sizeof(char)*msglen);
	memset(mac,0,sizeof(mac));
	memset(msg,0,sizeof(msg));
	strcpy(msg,(nc_args->message));
	write(csocket,msg,strlen(msg));
	mac = HMAC(EVP_sha1(),key,sizeof(key)-1,(unsigned char *)msg,sizeof(msg)-1,NULL,NULL);
	
	char temp[3];
	memset(temp,0,sizeof(temp));
	sprintf(temp,"#%d",strlen(mac));
	write(csocket,mac,strlen(mac));
	write(csocket,temp,strlen(temp));
	if(nc_args->verbose ==1)
	{
		printf("\nyour message = %s",nc_args->message);
		printf("\nthe message length = %d",msglen);
		printf("\nmac = %s length of mac=%d",mac,strlen(mac));
	}
	printf("\nMessage sent");
}
int checkSelectedBytes(int bytes, int offset, FILE *fp)
{
	int flag=0;
	fseek(fp,0L,SEEK_END);
	int endpos = ftell(fp);
	if(bytes>(endpos-offset))
	{

		flag = 1;
	}
	fseek(fp,offset,SEEK_SET);
	return flag;
}
void sendSelectedBytes(FILE *fp,int csocket,int bytes,int verbose)
{
	if(fp==NULL)
	{
		return;
	}
	int i=0;
	unsigned char *mac = (unsigned char *)malloc(H_SIZE);
	char *buffer = malloc(sizeof(char)*bytes);
	memset(buffer,0,sizeof(buffer));
	fread(buffer,1,bytes,fp);	
	
	write(csocket,buffer,strlen(buffer));
	memset(mac,0,sizeof(mac));
	mac = HMAC(EVP_sha1(),key,sizeof(key)-1,buffer,sizeof(buffer)-1,NULL,NULL);
	char temp[3];
	memset(temp,0,sizeof(temp));
	sprintf(temp,"#%d",strlen(mac));
	write(csocket,mac,strlen(mac));
	write(csocket,temp,strlen(temp));
	if(verbose == 1)
	{
		printf("\n This is msg = %s",buffer);
		printf("\n This is mac = %s",mac);
		printf("\n this is temp= %s", temp);
	}
	printf("\n %d bytes from file have been sent",bytes);
	fclose(fp);
}
void sendFile(nc_args_t * nc_args,int csocket)
{
	FILE *fp;
	unsigned char *mac = (unsigned char *)malloc(H_SIZE);
	char buffer[BUF_SIZE];
	char *completeFile;
	setMemoryAllocationParameters();
	fp = fopen(nc_args->filename,"r");
	if(fp==NULL)
	{
		printf("the file does not exist");
		return;
	}
	//if((nc_args->offset)>0)
	int fileSize,flag=0;
	fseek(fp,0L,SEEK_END);
	fileSize = ftell(fp)-(nc_args->offset);
	completeFile = malloc((sizeof(char))*fileSize);
	memset(completeFile,0,sizeof(completeFile));
	fseek(fp,(nc_args->offset),SEEK_SET);
	
	if((nc_args->n_bytes)>0)
	{	
		flag = checkSelectedBytes(nc_args->n_bytes,nc_args->offset,fp);
		if(flag==0)
		{
			sendSelectedBytes(fp,csocket,nc_args->n_bytes,nc_args->verbose);
			return;
		}
	}
	while(fread(buffer,1,BUF_SIZE,fp))
	{	
		write(csocket,buffer,strlen(buffer));
		strcat(completeFile,buffer);
		memset(buffer,0,sizeof(buffer));
	}
	memset(mac,0,sizeof(mac));
	
	mac = HMAC(EVP_sha1(),key,sizeof(key)-1,completeFile,sizeof(completeFile)-1,NULL,NULL);
	
	char temp[5];
	memset(temp,0,sizeof(temp));
	sprintf(temp,"#%d",strlen(mac));
	write(csocket,mac,strlen(mac));
	write(csocket,temp,strlen(temp));
	
	if(nc_args->verbose == 1)
	{
		printf("\nThis is the file data %s\nlength of file portion which is sent %d",completeFile,strlen(completeFile));
		printf("\n This is mac = %s",mac);
		printf("\n this is temp= %s", temp);
	}
	printf("\n your file is sent");
}
int main(int argc, char * argv[]){
  nc_args_t nc_args;
  int sockfd;
  fflush(stdout);
  //initializes the arguments struct for your use
  parse_args(&nc_args, argc, argv);
  sockfd = connectToServer(&nc_args);
  if(sockfd==-1)
	return 0;
  if(nc_args.message_mode==1)
  {
	sendMsg(&nc_args,sockfd);
  }
  else
	sendFile(&nc_args,sockfd);
  closeConnection(sockfd);
  return 0;
}

