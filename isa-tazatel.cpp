/* 
** Project ISA 2019/2020
** Variant: Whois tazatel
** Author: Samuel Stuchly
** Login: xstuch06
*/


#include <iostream> 
#include <cstring>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
//#include <netinet/in.h>
//#include <arpa/nameser.h>
//#include <resolv.h>




#define ANSWER_BUF 2048


struct addrinfo * given_hostname = (struct addrinfo *)malloc(sizeof(struct addrinfo));      // for passing info about given hostname or IP between functions
struct addrinfo * whois_server = (struct addrinfo *)malloc(sizeof(struct addrinfo));        // for passing info about whois server between functions

std::string whois_ip;           // ip adress of whois server
std::string given_ip;           // given ip address if not hostname
std::string given_domain;     // given hostname if not ip address


// flags and strings for parsing arguments
std::string q_content,w_content,d_content;
bool q_flag,w_flag,d_flag;



// help function that displays usage of this program
void help()
{
    std::cout << "Usage: ./isa -q <IP|Hostname> -w <IP| WHOIS server hostname> [-d <IP>]" << std::endl;
}

// function checks if IP address provided contains a character string representing a valid network address 
// inet_pton() - tries to convert ip address text to binary, on success returns 1 on fail 0 
bool is_ip_addr(const char* content)
{
	unsigned char buf[sizeof(struct in6_addr)];    

	if (inet_pton(AF_INET,content,buf))		
	{
		return true; 		// is IPv4 address
	}
	else if (inet_pton(AF_INET6, content, buf))
	{
		return true;		// is IPv6 address
	}
	else
	{
		return false;		// not an IP adress 
	}		
}



// function checks if hostname or ip provided is a valid hostname or ip with use of getaddrinfo()
// code for this function was inspired by https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d and http://man7.org/linux/man-pages/man3/getaddrinfo.3.html
bool is_hostname_or_IP(const char * name_or_ip,struct addrinfo** rp, bool whois_check)
{
    int sfd;
    struct addrinfo hints;
    struct addrinfo *result;
    int rv;
    void* ptr;
    char dst_ipv6[300];
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
  
    
    rv= getaddrinfo(name_or_ip, NULL, &hints, &result);
    if (rv != 0) {
        fprintf(stderr, "Error: getaddrinfo: %s\n", gai_strerror(rv));
        return false;
    }
    
    //getaddrinfo retruns in result list of structures with addresses 
    for (*rp = result; *rp != NULL; *rp = (*rp)->ai_next) {
        
        switch ((*rp)->ai_family)
        {
            case AF_INET:
                ptr = &((struct sockaddr_in *) (*rp)->ai_addr)->sin_addr;
                break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *) (*rp)->ai_addr)->sin6_addr;
                break;
        }
         
        inet_ntop ((*rp)->ai_family, ptr, dst_ipv6, 100);       //convert ip from binary to text 
        std::string string_dst(dst_ipv6);
        if (whois_check){
            whois_ip = string_dst;    
            
        }
        else
        {
            given_domain = name_or_ip;
            given_ip = string_dst;
           
        }
        
        break;      // we are using the first address provided by getaddrinfo()
    }
    
    return true;
}

bool is_WHOIS_hostname(const char* name_or_ip)
{
    if (is_hostname_or_IP(name_or_ip,&whois_server,true)){        
        if (!(is_ip_addr(name_or_ip))){
            if ((strncmp(name_or_ip,"whois.",6) == 0) || ((strncmp(name_or_ip,"www.whois.",10) == 0))){
                return true;        //hostname is of right format with prefix whois. but sometime can  have www. prefix before 
            }
            else       
            {
                std::cerr << "Error: Input hostname does not have prefix 'whois.'" << std::endl;
                help();
                exit(EXIT_FAILURE);
            }
            
        }
        else{
            return true;        // IP adsress could be whois server
            // TODO:  BUG : if ip address is not one of whois server program will connect to the ip address and bassicly wait forever...
            // could maybe be fixed by gethostbyaddr(), will be fixed if i had time
        }
    }
    else {
        return false;       // not a hostname nor an IP adress
    }
}


// Function takes whole answer from whois server and parses it to dsiplay only desired info 
// this code was inspired by https://en.cppreference.com/w/c/string/byte/strtok
void compose_output(char *answer_str){

    char *input = answer_str;
    printf("=== WHOIS ===\n");
    char *token = strtok(input, "\r\n");    //split the answer by "\r\n" to read it in lines
    while(token) {
        std::string mystring(token);
        // list of keywords of info that we want to show in the output
        // some keywords have to be added with capital letters because certain whois servers like whois.arin.net dont return answers in ussual format like whois.iana.org,whois.nic.cz,whois.ripe.net etc.
        std::string keywords [25] = {"inetnum:", "netname:", "descr:", "country:", "address:", "phone:", "admin-c:","org:","domain:","remarks:","refer:","name:","NetRange:","Organization:","Address:","Country:","Ref:","Domain:","Name:","Contact:","Phone:","Email:","Street:","City:","Code:"};
        for (int i=0;i<25;i++){
            if (mystring.find(keywords[i]) != std::string::npos) {
                puts(token);
            }
        }
        token = strtok(NULL, "\r\n");       //split the answer by "\r\n" to read it in lines
    }

}
// Function makes a quiry to whois server 
// bool ip serves as indicator if -q is ip address or domain name
void ask_whois(bool ip,bool second_call){

    
    char dst_ipv6[INET6_ADDRSTRLEN];
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd;
    struct sockaddr_in server;
    char answer_buffer[ANSWER_BUF];
    int bytes_read;
    int bytes_total = 0;
    void * ptrad;
    char messege[100];
    const char* host;
    struct sockaddr_in server4;
    struct sockaddr_in6 server6;


    // sfd => socket file descriptor
    sfd = socket(whois_server->ai_family, whois_server->ai_socktype,
                    whois_server->ai_protocol);
        
        if (sfd == -1){
            fprintf(stderr,"Error: could not find socket! \n");
            exit(EXIT_FAILURE);
        }
   

    // check if IP addres if whois server is in IPv4 or IPv6 and then connect accordingly

    if (whois_server->ai_family == AF_INET){
        ptrad = &((struct sockaddr_in *) whois_server->ai_addr)->sin_addr;
        
        
         bzero(&server4, sizeof(server4));

         server4.sin_family =AF_INET;           // whois_server->ai_family;
        server4.sin_addr.s_addr = inet_addr(whois_ip.c_str());      // converts IPv4 adress from text to binary
        server4.sin_port = htons( 43 );         // WHOIS server listens on port 43
         
        int c =connect( sfd , (const struct sockaddr*) &server4 , sizeof(server4) );
        if( c < 0)
        {
            perror("Error : connect failed");
            exit(EXIT_FAILURE);

        }
        else{
                    
            if (!ip){
                host = given_ip.c_str();
            }
            else
            {
                host = given_domain.c_str();
            }
            sprintf(messege , " %s\r\n" , host);    // query to WHOIS server must be in format "Info about Smith<CR><LF>", based on https://tools.ietf.org/html/rfc3912
            int i = send(sfd , messege, 100 , 0);
            
            if( i < 0)
            {
                perror("error: send failed");
                exit(EXIT_FAILURE);
            } 
        }


    }
    else if (whois_server->ai_family == AF_INET6)
    {
        ptrad = &((struct sockaddr_in6 *) whois_server->ai_addr)->sin6_addr;
        
        bzero(&server6, sizeof(server6));

        server6.sin6_family =AF_INET6;      // whois_server->ai_family;

        server6.sin6_port = htons( 43 );    // WHOIS server listens on port 43
        
        inet_pton(AF_INET6,whois_ip.c_str(),&server6.sin6_addr);            // converts IP adress from text to binary 
        int c =connect( sfd , (const struct sockaddr*) &server6 , sizeof(server6) );
        if( c < 0)
        {
            perror("connect failed");
            exit(EXIT_FAILURE);
        }
        else{
                   
            if (!ip){
                host = given_ip.c_str();
            }
            else
            {
                host = given_domain.c_str();
            }
            sprintf(messege , "%s\r\n" , host);        // query to WHOIS server must be in format "Info about Smith<CR><LF>", based on https://tools.ietf.org/html/rfc3912
            int i = send(sfd , messege, 100 , 0);
                        if( i < 0)
            {
                perror("Error: send failed");
                exit(EXIT_FAILURE);
            } 
        }
    }
    else
    {
        //should not be reached , butjust in case , i dont want unexpected segmentation fault and 0 points :) 
        fprintf(stderr,"Other than AF_INET or AF_INET6 ai_family was input somehow. \n"); 
        exit(EXIT_FAILURE);
    }
    

    char * answer = (char* )malloc(100* sizeof(char)); // allocate memory for whois answer
    if(answer == NULL)
		{
			fprintf(stderr,"malloc failed");
            exit(EXIT_FAILURE);
		}

    // data from whois can come in more than one answer, thats why we use while to keep recieving
	while( (bytes_read = recv(sfd , answer_buffer , sizeof(answer_buffer) , 0) ) )      
	{
		answer = (char *)realloc(answer , bytes_read + bytes_total);    // allocate more space for reaciaved data
		if(answer == NULL)
		{
			fprintf(stderr,"realloc failed");
            exit(EXIT_FAILURE);
		}
		memcpy(answer + bytes_total ,answer_buffer , bytes_read);   // copy data into answer string
		bytes_total += bytes_read;                  
		
		
	}
	
	fflush(stdout);
	
	answer = (char*)realloc(answer , bytes_total + 1);
	*(answer + bytes_total) = '\0';   // end the string with '\0'

    
    
    std::string err_string = "ERROR:101: no entries found"; // for example on whois.nic.cz 
    std::string err_string2 = "NAMESERVER NOT FOUND";       // for axample on whois.sk-nic.sk
    std::string answer_str(answer);
    if ((answer_str.find(err_string) != std::string::npos) || (answer_str.find(err_string2) != std::string::npos) ) 
    {
        
        
        if (second_call){
            std::cout <<  "==== WHOIS ====\n" << err_string << std::endl;
        }
        second_call = true;
        if (!ip)        // first try ip address then hostname;
        {
            ask_whois(true,second_call);
        }
        
    
    }
    else{
        compose_output(answer);
	//puts(answer); 	/* Uncomment this function to print entire answer from Whois. */ 
    }
	
	close(sfd);
    free(answer);
}

// function for parsing arguments of the program with usage of getopt function
void parseArguments(int argc, char *argv[])
{

    int c;
    std::string getoptStr = "+:q:w:d:";
	// flags show if the option has been set already
	q_flag = false;
	w_flag = false;
	d_flag = false;

    // parses arguemnts until there is no more then returns -1
    // getopt implementation was inspired from linux man pages http://man7.org/linux/man-pages/man3/getopt.3.html
    while ((c = getopt (argc, argv, getoptStr.c_str())) != -1)
    switch(c)
    {	
        case 'q':
            if (q_flag)
            {
                std::cerr << "Error: Same paramater was input more than once." << std::endl; 	
                help();
                exit(EXIT_FAILURE);
            }
            q_flag = true;
            if (optarg)
            {
                q_content = std::string{optarg};
                
				if (is_hostname_or_IP(q_content.c_str(),&given_hostname,false))
				{
        
					break;	
				}
				else
				{
					std::cerr << "Error: Option 'q' value is of incorrect format." << std::endl;
                	help();
                	exit(EXIT_FAILURE);
				}
            }
            break;

        case 'w':
            if (w_flag)
            {
                std::cerr << "Error: Same paramater was input more than once." << std::endl;
                help();
                exit(EXIT_FAILURE);
            }
            w_flag = true;
            if (optarg)
            {
                
                w_content = std::string{optarg};
				if (is_WHOIS_hostname(w_content.c_str()))
				{
					break;	
				}
				else
				{
					std::cerr << "Error: Option 'w' value is of incorrect format." << std::endl;
                	help();
                	exit(EXIT_FAILURE);
				}
            }
            break;
			
		case 'd':
            if (d_flag)
            {
                std::cerr << "Error: Same paramater was input more than once." << std::endl;
                help();
                exit(EXIT_FAILURE);
            }
            d_flag = true;
            if (optarg)
            {
                d_content = std::string{optarg};
				if (!is_ip_addr(d_content.c_str()))
				{
                     // even though functioanlity for parameter d is not implemented,foramt check is still active
					std::cerr << "Error: Option 'd' value is of incorrect format." << std::endl;
                	help();
                	exit(EXIT_FAILURE);
				}
            }
            break;


		case ':':
			std::cerr << "Error: Missing parameter value." << std::endl;
            help();
            exit(EXIT_FAILURE);

        default: // same as ? in this case
            std::cerr << "Error: Incorrect option." << std::endl;
            help();
            exit(EXIT_FAILURE);
    }

	// making sure requeired arguments were input

    if (!q_flag)
    {
        std::cerr << "Error : option 'q' missing !"  << std::endl;
        help();
        exit(EXIT_FAILURE);
    }
	if (!w_flag)
    {
        std::cerr << "Error : option 'w' missing !"  << std::endl;
        help();
        exit(EXIT_FAILURE);
    }

	// -d option is not required so in case it wasnt input it is set to default

	if (!d_flag)
    {
        d_content = "";      // implicitně se používá DNS resolver v operačním systému
                                        // -d parameter functionality is not implemented
    }

    // catches any other unwanted arguemts

    for (int i = optind; i < argc; i++)
    {
        fprintf( stderr,"Error: Unknown argument: '%s'.\n",argv[optind]); 
		help();
        exit(EXIT_FAILURE);
    }
}


// Program will take parameters -q => IP or hostname, -w => IP or hostname of whois server.
// Program will query whois server specified by parameter -w and display information recieved about IP or hostname specified by paramter -q.

int main(int argc, char** argv) {
 
    
    parseArguments(argc,argv);  
    if (is_ip_addr(q_content.c_str())){
        ask_whois(true,true);   //second_call (second argument of ask_whois() )is true because we try only one time
    }
    else{
        ask_whois(false,false);     //second call (second argument of ask_whois() ) is false because we want to try both ip and hostname;
    }

    free(whois_server);
    free(given_hostname);
    
    return EXIT_SUCCESS;

}


       
