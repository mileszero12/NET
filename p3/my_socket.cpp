#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <errno.h>
#include <resolv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
#define BLEN 1024

#define FAIL    -1
char buf[BLEN];
int n; //recv()
string temp;

//checking overflow
void check(char* buf, int n, int sd)
{
	temp = buf;
	while(n == BLEN)
	{
		memset((char *)buf, 0, BLEN);
		n=recv(sd, buf, BLEN, 0);
		//overflow = 0;
		temp = temp + buf;
		if(n < BLEN)
			cout<<temp<<endl;
	}
}


SSL_CTX* InitCTX(void)
{   
	const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stdout);
        exit(1);       
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{   
	X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        cout << "Server certificates:\n";
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        cout << "Subject:\n" << line;
        free(line); 
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        cout << "Issuer:\n" << line;
        free(line); 
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}


int main(int argc, char *argv[]){
	//wrong input form
	string fstSeg = argv[0];
	if(argc < 3)
	{
		cout<<"ERROR: Input format: " + fstSeg + "hostname port\n";
		exit(0);
	}
	//SSL
	SSL_CTX *ctx;
	SSL *ssl;
    SSL_library_init();
    ctx = InitCTX();
    
	//address
	struct sockaddr_in suckit;
	memset((char *) &suckit, 0, sizeof(suckit));
	suckit.sin_addr.s_addr = inet_addr(argv[1]);
	suckit.sin_family = AF_INET;
	suckit.sin_port = htons(atoi(argv[2]));
	//creating socket
	int sd;
	sd = socket(PF_INET, SOCK_STREAM, 0);
	if(sd < 0)
	{
		cout<<"ERROR creating socket\n";
		exit(0);
	}
	//connecting
	if (connect(sd, (struct sockaddr*)&suckit, sizeof(suckit)) < 0)
	{
		cout<<"ERROR connecting\n";
		exit(0);
	}
	//SSL
	ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, sd);
    SSL_connect(ssl);
    ShowCerts(ssl);
	//sucessful connection
	memset((char *)buf, 0, BLEN);
	n=SSL_read(ssl, buf, BLEN);
	if(n < BLEN)
		cout<<buf<<endl;
	else
		check(buf, n, sd);

	//connected!
	while(true)
	{
	//two options to choose
		string opt; 
		cout<<"Enter 1 for Register, 2 for Login: ";
		cin>>opt;

		//Register
		if(opt=="1")
		{
			//REGISTER#name
			memset((char *)buf, 0, BLEN);
			string name, balance;
			cout<<"Enter the name you want to register: ";
			cin>>name;
			cout<<"Enter your account balance: ";
			cin>>balance;
			name = "REGISTER#" + name + "@" + balance;
			SSL_write(ssl, name.c_str(), name.size());
			n=SSL_read(ssl, buf, BLEN);
			if(n < BLEN)
				cout<<buf<<endl;
			else
				check(buf, n, sd);
		}

		//Login
		else if(opt=="2")
		{
			//LOGIN
			memset((char *)buf, 0, BLEN);
			cout<<"Enter your name: ";
			string inputName; cin>>inputName;
			cout<<"Enter the port number: ";
			string inputNum; cin>>inputNum;
			inputName = inputName + "#" + inputNum;
			SSL_write(ssl, inputName.c_str(), inputName.size());
			n=SSL_read(ssl, buf, BLEN);
			if(n < BLEN)
			{
				temp = buf;
				cout<<buf<<endl;
			}
			else
				check(buf, n, sd);			

			string action;
			string msg;
			
			while(strcmp(temp.c_str(), "220 AUTH_FAIL\n")!=0)
			{
				cout<<"Enter the number of actions you want to take.\n";
				cout<<"1 to ask for the latest list, 8 to Exit: ";
				cin>>action;
				if(action=="1")
				{
					msg="List";
					SSL_write(ssl, msg.c_str(), msg.size());
					memset((char *)buf, 0, BLEN);
					n= SSL_read(ssl, buf, BLEN);
					if(n < BLEN)
						cout<<buf<<endl;
					else
						check(buf, n, sd);
				}
				else if(action=="8")
				{
					msg="Exit";
					SSL_write(ssl, msg.c_str(), msg.size());
					memset((char *)buf, 0, BLEN);
					n=SSL_read(ssl, buf, BLEN);
					if(n < BLEN)
						cout<<buf<<endl;
					else
						check(buf, n, sd);
					close(sd);
					SSL_shutdown(ssl);
					SSL_free(ssl);
					SSL_CTX_free(ctx);
					exit(0);
					//Bye	
				}
			}
		}
	}
}
