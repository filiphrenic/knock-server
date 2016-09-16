#include "knock_server.h"

int tcp_sock, max_sock, max_udp, state;
fd_set sockets, tmp;

// *******
// * TCP *
// *******

void StartTCPApplication(){
    tcp_sock = TCPserver(TCP_PORT, BACKLOG);
    max_sock = MAX(max_sock, tcp_sock);
    FD_SET(tcp_sock, &tmp);
    Log("Started TCP app on port %s\n", TCP_PORT);
}

void ProcessTCPClient(){
    int client_sock;
    struct sockaddr client;
    socklen_t client_len;
    
    client_sock = Accept(tcp_sock, &client, &client_len);
    Writen(client_sock, "Hello world", 12);
 
    Log("TCP app finished, closing connection\n");
    
    Restart();
}

// *******
// * UDP *
// *******

int UdpListener(char* port){
    int socket = UDPserver(port);
    return socket;
}

struct sockaddr* RecieveFromUDP(int socket, char* buff){
    struct sockaddr* sa = MLC(struct sockaddr, 1);
    socklen_t len = sizeof(struct sockaddr);
    
    if (Recvfrom(socket, buff, BUFFER_LEN_SMALL, 0, sa, &len) < 0) {
        Warnx("Error while recieving on UDP socket [%d]\n", socket);
        return NULL;
    }
    return sa;
}

void IgnoreRecieve(int udp_sock){
    Recvfrom(udp_sock, NULL, 0, 0, NULL, NULL);
}

// **********
// * Helper *
// **********

char RandomLetter(){
    int r = rand() % ('Z' - 'A' + 1);
    return r + 'A' + (rand() % 2 ? ('a'-'A') : 0);
}

// changes challenge
void XOR(char* challenge, char* tajni_kljuc){
    challenge[0] ^= tajni_kljuc[0];
    challenge[1] ^= tajni_kljuc[1];
}

void Restart(){
    if (tcp_sock != -1){
        Close(tcp_sock);
        FD_CLR(tcp_sock, &tmp);
    }
    sockets = tmp;
    tcp_sock = -1;
    max_sock = max_udp;
    state = START;
}

int main(int argc, char** argv) {
    
    char ch;
    int idx, i, s;
    char* lozinka = MLC(char, BUFFER_LEN_SMALL);
    char* tajni_kljuc = MLC(char, 2);
    int lozinka_len;
    
    int udp[5];
    int timeout = TIMEOUT;
    struct timeval t;
    char* buff = MLC(char, BUFFER_LEN_SMALL);
    struct sockaddr* sa;
    char challenge[3];
    challenge[2] = 0;
    
    tcp_sock = -1;
    max_sock = 0;
    max_udp = 0;
    state = START;
    
    // read options
    while ( (ch=getopt(argc, argv, "t:")) != -1 ){
        if (ch == 't') timeout = atoi(optarg);
        else Usage(argv[0]);
    }
    if (argc - optind != 7) Usage(argv[0]);
    idx = optind;
    
    // init parameters
    t.tv_sec = timeout;
    t.tv_usec = 0;
    lozinka_len = strlen(argv[idx]);
    if (lozinka_len > BUFFER_LEN_SMALL){
        Errx(MP_PARAM_ERR, "Lozinka je pre duga, maximalno %d znakova!", BUFFER_LEN_SMALL);
    }
    strncpy(lozinka, argv[idx++], lozinka_len);
    strncpy(tajni_kljuc, argv[idx++], 2);
    
    // create udp listeners
    for(i=0; i<5; i++){
        udp[i] = UdpListener(argv[idx++]);
        FD_SET(udp[i], &sockets);
        max_udp = MAX(max_udp, udp[i]);
        Log("Started listening on port %s [udp]\n", argv[idx-1]);
    }
    
    max_sock = max_udp;
    
    while(1){
        
        Log(
                "Current state = %s\n", 
               (state == START    ? "Send password to u1" 
             : (state == XOR_WAIT ? "Solve challenge on u2" 
                                  : "Communicate with TCP"))
        );
        
        tmp = sockets;
        
        s = select(max_sock+1, &sockets, NULL, NULL, &t);
        if (s==-1)
            Error("select");
        
        if (s==0){ // timeout
            Log("Timeout occurred, restarting\n");
            Restart();
            continue;
        }
        
        for(i=0;i<=max_sock;i++){
            
            if (!FD_ISSET(i, &sockets)) continue;
            
            if (i == udp[2] || i == udp[3] || i == udp[4]){
                Log("UDP control port shouldn't receive anything, restarting\n");
                IgnoreRecieve(i);
                Restart();
                break;
            }
            
            if (i == udp[0]){
                if (state != START){
                    Log("u1 got something but shouldn't have, restarting\n");
                    IgnoreRecieve(i);
                    Restart();
                    break;
                }
                
                sa = RecieveFromUDP(udp[0], buff);
                if (strncmp(lozinka, buff, lozinka_len)){
                    Log("Passwords don't match, restarting\n");
                    IgnoreRecieve(i);
                    Restart();
                    break;
                }
                
                challenge[0] = RandomLetter();
                challenge[1] = RandomLetter();
                Sendto(udp[0], challenge, 2, 0, sa, sizeof(struct sockaddr));
                Log("Challenged client with %s\n", challenge);
                XOR(challenge, tajni_kljuc);
          
                state = XOR_WAIT;
            }
            
            if (i == udp[1]){
                if (state != XOR_WAIT){
                    Log("u2 got something but shouldn't have, restarting\n");
                    IgnoreRecieve(i);
                    Restart();
                    break;
                }
                
                sa = RecieveFromUDP(udp[1], buff);
                if (strncmp(challenge, buff, 2)){
                    Log("Challenge failed, restarting\n");
                    IgnoreRecieve(i);
                    Restart();
                    break;
                }
                
                StartTCPApplication();
                state = TCP_WAIT;
            }
            
            if (i == tcp_sock){
                
                if (state != TCP_WAIT){
                    // ovo se nikad nebi trebalo dogoditi jer je tcp on akko je state == TCP_WAIT
                    Log("This can't happen, which means that tcp application didn't close.\n");
                    Restart();
                    break;
                }
                
                ProcessTCPClient();
                state = START;
            }
            
        }
        
        sockets = tmp;
        
    }
    
    // never exits while loop
    
    free(buff);
    free(lozinka);
    free(tajni_kljuc);
    return (EXIT_SUCCESS);
}

