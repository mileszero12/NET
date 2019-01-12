#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sstream>
#include <errno.h>
#include <malloc.h>
#include <resolv.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <pthread.h>
#include <queue>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

//#define PORT 8477
#define BACKLOG 5
#define BLEN 1024
#define POOLSIZE 10
#define LISTSIZE 1024
#define FAIL    -1
struct sockaddr_in serv_addr, cli_addr;

string s_msg;
string r_msg;
int sd, pos;
fd_set fdset, readfds;
queue<int> todo;
pthread_mutex_t mutex1;
pthread_mutex_t mutex2;

string list[LISTSIZE];//register list
string balance[LISTSIZE];//online account balance
string online[LISTSIZE];//online list
int regiCount = 0;//num of register
int onlineCount = 0;//num of online
bool login = 0;//check login
bool check = 0;//check register

    SSL_CTX *ctx;
    SSL *ssl[LISTSIZE];

//check if user is root
int isRoot()
{
    if (getuid() != 0)
        return 0;
    else   
        return 1;    
}

//Init server instance and context
SSL_CTX* InitServerCTX(void)
{   
    const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  //load & register all cryptos, etc. 
    SSL_load_error_strings();   // load all error messages */
    method = SSLv3_server_method();  // create new server-method instance 
    ctx = SSL_CTX_new(method);   // create new context from method
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

//Load the certificate 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    //set the local certificate from CertFile
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    //set the private key from KeyFile
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    //verify private key 
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

string trans(int i)
{
    stringstream ss;
    ss << i;
    return ss.str();
}

void communicate(int cur)
{
    login = 0;
    char buf[BLEN];
    memset(&buf,'\0', sizeof(buf));
    SSL_read(ssl[cur],&buf,sizeof(buf));
    r_msg = buf;
    
    //register#NAME@BALANCE
    if(r_msg.find("REGISTER#") != string::npos)
    {
        cout<<"register";
       
        r_msg = r_msg.substr(9);//name@balance
        pos = r_msg.find("@");
        string regiName = r_msg.substr(0, pos);

        check = 0;
        for(int i=1; i<LISTSIZE; i++)
        {
            pos = list[i].find("@");
            if(list[i].substr(0, pos) == regiName)
                check = 1;
            //already registered
        }
        if(check == 0)
        {
            regiCount++;
            list[regiCount] = r_msg;
            s_msg = "100 OK\n";
            cout<<"new rigister\n";          
        }
        else
        {
            s_msg = "210 FAIL\n";
            cout<<"fail register\n";
        }
    }

    //list
    else if (r_msg.find("List") != string::npos)
    {
        cout<<"list\n";
        s_msg = "AccountBalance:" + balance[cur] + "\n";
        string c = trans(onlineCount);
        s_msg = s_msg + "Number of users:" + c + "\n";
        for(int i=1; i<LISTSIZE; i++)
            s_msg = s_msg + online[i];
    }

    //exit
    else if (r_msg.find("Exit") != string::npos)
    {
        cout<<"exit\n";
        s_msg = "Bye\n";
        onlineCount--;
        online[cur].clear();
        FD_CLR(cur, &fdset);
    }

    //login
    else if(r_msg.find("#") != string::npos)
    {
        cout<<"login\n";
        pos = r_msg.find("#");
        string name = r_msg.substr(0, pos);
        string port = r_msg.substr(pos+1);
        for(int i=1; i<LISTSIZE; i++)
        {
            pos = list[i].find("@");
            if(list[i].substr(0, pos) == name)
            {
                login = 1;
                memset((char *)buf, 0, BLEN);
                inet_ntop(AF_INET, &cli_addr.sin_addr, buf, INET_ADDRSTRLEN);
                string IP = buf;
                online[cur] = name + "#" + IP + "#" + port + "\n";
                balance[cur] = list[i].substr(pos+1);
                onlineCount++;
            }
        }
        if(login == 1)
        {
            s_msg = "AccountBalance:" + balance[cur] + "\n";
            string c = trans(onlineCount);
            s_msg = s_msg + "Number of users:" + c + "\n";
            for(int i=1; i<LISTSIZE; i++)
                s_msg = s_msg + online[i];
            cout<<"new login\n";
        }
        else
        {
            s_msg = "220 AUTH_FAIL\n";
            cout<<"fail login\n";
        }
    }
    else
    {
        cout<<r_msg<<"\n";
    }
}

void* request(void* arg){
    while(true)
    {
        pthread_mutex_lock(&mutex1);
        int temp = -100;
        if(!todo.empty())
        {
            temp = todo.front();
            todo.pop();
        }
        pthread_mutex_unlock(&mutex1);
        if(temp > 0)
        {
            communicate(temp);
            SSL_write(ssl[temp], s_msg.c_str(), s_msg.size());
        }
        //pthread lock
        else if(temp == -1)
        {
            pthread_mutex_unlock(&mutex2);
        }
    }
}

int main(int argc, char *argv[]){
    
    //wrong input
    if (argc < 2)
    {
        cout<<"Error input\n";
        exit(0);
    }
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!\n");
        exit(0);
    }

    SSL_library_init();
    printf("Initialize SSL library.\n");
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mykey.pem"); /* load certs */
    
    //thread
    pthread_t pool[POOLSIZE];
    for(int i = 0; i < POOLSIZE; i++)
    {
        pthread_create(&pool[i], NULL, request, NULL);
    }
    pthread_mutex_init(&mutex1, NULL);
    pthread_mutex_init(&mutex2, NULL);
    
    //addr
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[1]));
    
    //socket
    int sockfd;
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        cout<<"Error creating socket\n";
        exit(0);
    }
    
    //bind
    if(bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        cout<<"Error binding\n";
        exit(0);
    }
    
    //listen
    listen(sockfd, BACKLOG);
    printf("Waiting for client to connect...\n");
    //accept, an infinite loop
    int new_fd;
    int max_fd = sockfd;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    while(true)
    {
        FD_ZERO(&readfds);
        //cout<<"loop\n";
        readfds = fdset;
        pthread_mutex_lock(&mutex2);
        if(select(max_fd+1, &readfds, NULL, NULL, 0) > 0)
        {
            cout<<"1\n";
            for(int i=0; i<=max_fd; i++)
            {
                cout<<"2\n";
                //cout<<i<<endl;
                if(FD_ISSET(i, &readfds))
                {
                    cout<<"3\n";
                    if(i == sockfd)
                    {
                        cout<<"4\n";
                        socklen_t len = sizeof(cli_addr);
                        new_fd = accept(sockfd, (struct sockaddr*)&cli_addr, &len);
                        ssl[new_fd] = SSL_new(ctx);                        
                        SSL_set_fd(ssl[new_fd], new_fd);
                        SSL_accept(ssl[new_fd]);
                        
                        string str = "sucessful connection\n";
                        SSL_write(ssl[new_fd], str.c_str(), str.size());
                        FD_SET(new_fd, &fdset);
                        if(new_fd > max_fd)
                            max_fd = new_fd;
                        //cout<<"accept "<<a<<"\n";
                    }
                    else if(i != sockfd)
                    {
                        pthread_mutex_lock(&mutex1);
                        todo.push(i);
                        //cout<<a<<" push "<<i<<"\n";
                        pthread_mutex_unlock(&mutex1);
                        
                    }
                }
            }
        }
        pthread_mutex_lock(&mutex1);
        todo.push(-1);
        pthread_mutex_unlock(&mutex1);

        //pthread_mutex_unlock(&mutex2);
    }

}
