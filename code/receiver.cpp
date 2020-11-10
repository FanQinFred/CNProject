#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXSIZE 1500
#define MINSIZE 46

// SIZE:    6Bytes   6Bytes   2Bytes         46-1500Bytes   4Bytes
// MEANING: DA       SA       ProtocalType   PayLoad        FCS

// Mac Address
typedef unsigned char mac_addr[6];
//mac_addr my_mac = { 0x3D,0xE1,0x2D,0x6F,0xE9,0x34 };
mac_addr my_mac = { 0x00,0x00,0x00,0x00,0x00,0x00 };

unsigned char buffer[65536];

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
    if (pos = ftell(file) == -1L) {
        printf("%s\n", "File Tell Error!");
        exit(0);
    }
    return pos;
}

// Display MAC address
void show_mac_addr(unsigned char m[6]) {
    for (int i = 0;i < 6;i++) {
        printf("%02x", m[i]);
        if (i != 5) printf(":");
    }
}

// Show protocol type
void show_protocol(unsigned char m[2]) {
    for (int i = 1;i >= 0;i--) {
        printf("%02x", m[i]);
    }
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

// Determine whether the MAC address is the same
bool mac_same(unsigned char* dst_mac,unsigned char* my_mac,int mac_len){
	for(int i=0;i<mac_len;i++){
		if(dst_mac[i]!=my_mac[i]){
			return false;
		}
	}
	return true;
}

// Start accepting frames
void start_receive(char* fileinput) {
    FILE* fileIn;
    fileIn = OpenFile(fileinput);
    unsigned short frame_len;
    long int FrameIndex=1;
    // Receive each frame
    while (fread(&frame_len, sizeof(frame_len), 1, fileIn)) {
        if (frame_len == 0) break;
        // Determine the length of the frame so that it can be received at one time
        fread(buffer, sizeof(char), frame_len, fileIn);
        //CRC
        unsigned int crc32_result = crc32(buffer, frame_len - 4);
        unsigned char crc32_result_c[4];
        memcpy(crc32_result_c, &crc32_result, sizeof(crc32_result));
        // Judge whether the CRC check code is consistent
        bool bool_crc_same = crc32_result_c[3] == buffer[frame_len-1] &&
		                	 crc32_result_c[2] == buffer[frame_len-2] &&
			                 crc32_result_c[1] == buffer[frame_len-3] &&
			                 crc32_result_c[0] == buffer[frame_len-4] ;
        if (!bool_crc_same) {
			printf("CRC ERROR\n");
			exit(0);
		}
        //MAC
        unsigned char dst_mac[6];
        memcpy(&dst_mac, &buffer, 6);
        // Judge whether the MAC address is consistent
        bool bool_mac_same = mac_same(dst_mac,my_mac,6);
        if (!bool_mac_same) {
			printf("MAC ERROR\n");
			exit(0);
		}
		printf("<-----------------------Frame Start-------------------------->\n");
		printf("The Content of The %ld th Frame is: \n",FrameIndex);
		printf("DA_MAC:\n");
        show_mac_addr(dst_mac);
		printf("\n");
			
        unsigned char src_mac[6];
        memcpy(&src_mac, &buffer[6], 6);
        printf("SA_MAC:\n");
        show_mac_addr(src_mac);
        printf("\n");

        unsigned char protocol_type[2];
        memcpy(&protocol_type, &buffer[12], 2);
        printf("ProtocalType:\n");
        show_protocol(protocol_type);
        printf("\n");

        unsigned char* payload[1500];
        memcpy(&payload, &buffer[14], frame_len-18);
        printf("PayLoad:\n");
        printf("%s\n", payload);
        printf("<--------------------------Frame END--------------------------->\n\n");
        FrameIndex++;
    }
}

int  main() {
    char fileinput[] = { "../data/2.txt" };
    // 1. Correct reception
    start_receive(fileinput);
    // 2. Wrong MAC address
    // 3. CRC error
    return 0;
}
