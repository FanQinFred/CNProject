#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

unsigned char VersionAndIHL=0x45;
unsigned char TOS=0x00;
unsigned int IPv4_TotalLength=

// 4 bit
int IPv4_version=0b0100;
// 4 bit
int IPv4_IHL=0b0000;
// 8 bit
int IPv4_TOS=
// 16 bit
int IPv4_TotalLength=
// 16 bit
int IPv4_Identification=
// 1 bit
int IPv4_NoFunc=
// 1 bit
int IPv4_DF=
// 1 bit
int IPv4_MF=
// 13 bit
int IPv4_FragmentOffset=
// 8 bit
int IPv4_TimeTolive=
// 8 bit
int IPv4_Protocol=
// 16 bit
int IPv4_HeaderCheckSum=
// 32 bit
int IPv4_SourceAddr=
// 32 bit
int IPv4_DesAddr=
// not sure bit
int IPv4_Option=

typedef unsigned char p11[6];



// CheckSum
unsigned int checkSum(unsigned char* data, int len) {

}

// Merge
unsigned short make_IPacket() {

}

// Send
void send_IPacket() {

}