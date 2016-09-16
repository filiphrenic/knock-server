#include "mrepro.h"

#define TCP_PORT "1234"
#define TIMEOUT  10

enum{START, XOR_WAIT, TCP_WAIT};

void StartTCPApplication();
void ProcessTCPClient();

int UdpListener(char* port);
struct sockaddr* RecieveFromUDP(int socket, char* buff);
void IgnoreRecieve(int udp_sock);

char RandomLetter();
void XOR(char* challenge, char* tajni_kljuc); // changes challenge
void Restart();

void Log(const char* fmt, ...){
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

void Usage(const char* name){
    Errx(MP_PARAM_ERR, "Usage: %s [-t timeout] lozinka tajni_kljuc u1 u2 u3 u4 u5", name);
}