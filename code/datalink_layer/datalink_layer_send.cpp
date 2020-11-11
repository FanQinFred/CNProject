#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

#define MAXSIZE 1500
#define MINSIZE 46

// SIZE:    6Bytes   6Bytes   2Bytes         46-1500Bytes   4Bytes
// MEANING: DA       SA       ProtocalType   PayLoad        FCS

// Mac Address
typedef unsigned char mac_addr[6];
mac_addr DesMacAddr = { 0x3D,0xE1,0x2D,0x6F,0xE9,0x34 };
mac_addr SrcMacAddr = { 0x34,0xE1,0x2D,0x6F,0xE9,0x3D };

// Data source and data destination
FILE* fileIn, * fileOut;
// The position of the last frame
long int LastFramePos;
long int PayLoadCount,AllByteCount;
long int RestByteCount,LackByteCount;

// OpenFile more safe
FILE* OpenFile(char* fileinput) {
    FILE* file;
    if ((file = fopen(fileinput, "r+")) == NULL) {
        printf("%s\n", "File Open Error!");
        exit(0);
    }
    return file;
}

// Tell file frame position
long int ftellSafe(FILE* file) {
    long int pos;
    if ((pos = ftell(file)) == -1L) {
        exit(0);
    }
    return pos;
}

// CRC checker
unsigned int crc32(unsigned char* data, int len) {
    unsigned int crc = 0xFFFFFFFF;
    for (int i = 0;i < len;i++) {
        crc = crc ^ data[i];
        for (int j = 0;j < 8;j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

// Merge data to form frames
unsigned short make_frame(mac_addr* dst, mac_addr* src, unsigned short protocol, unsigned char* payload, int payloadlen, unsigned char* result) {
    memcpy(&result[0], dst, 6);
    memcpy(&result[6], src, 6);
    memcpy(&result[12], &protocol, sizeof(protocol));
    memcpy(&result[14], payload, payloadlen);
    unsigned int crc32_result = crc32(result, payloadlen + 14);
    memcpy(&result[14 + payloadlen], &crc32_result, sizeof(crc32_result));
    return 18 + payloadlen;
}

// Ready to send a frame
void send_frame(unsigned char* frame_data, unsigned short len, FILE* file) {
    fwrite(&len, sizeof(len), 1, file);
    //frame_data[len-1]=~frame_data[len-1];
    fwrite(frame_data, sizeof(char), len, file);
}

// Start send
void datalink_layer_send(unsigned char* buf,int len){
    long FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, buf, len, buf);
    // Data destination
    char fileoutput[] = { "../data/2.txt" };
    send_frame(buf, FrameLength, OpenFile(fileoutput));
}