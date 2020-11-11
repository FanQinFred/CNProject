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

// Send a frame
void send_frame(unsigned char* frame_data, unsigned short len, FILE* file) {
    fwrite(&len, sizeof(len), 1, file);
    //frame_data[len-1]=~frame_data[len-1];
    fwrite(frame_data, sizeof(char), len, file);
}

void start_send(char* fileinput, char* fileoutput) {
    long int i;
    fileIn = OpenFile(fileinput);
    fileOut = OpenFile(fileoutput);
    fseek(fileIn, 0, SEEK_END);
    AllByteCount = ftellSafe(fileIn);
    PayLoadCount = AllByteCount / 1500;
    rewind(fileIn);
    // Split the data of the file, then each data is processed after segmentation
    for (int j = 0; j <= PayLoadCount; j++) {
        unsigned char data[MAXSIZE];
        unsigned char buf[1536];
        int FrameLength;
        // The last frame
        if (j != PayLoadCount) {
            fread(data, sizeof(char), 1500, fileIn);
            FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, data, 1500, buf);
            send_frame(buf, FrameLength, fileOut);
        }
        else {
            LastFramePos = ftellSafe(fileIn);
            RestByteCount = AllByteCount - PayLoadCount * 1500;
            LackByteCount = MINSIZE - RestByteCount;
            fread(data, sizeof(char), AllByteCount - LastFramePos, fileIn);
            // The frame size is less than 46 bytes
            if (LackByteCount > 0) {
                for (i = 0;i < LackByteCount; i++) {
                    data[RestByteCount++] = 0x00;
                }
                FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, data, 46, buf);
                send_frame(buf, FrameLength, fileOut);
            }
            else {
                FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, data, RestByteCount, buf);
                send_frame(buf, FrameLength, fileOut);
            }
        }

    }
    fclose(fileIn);
    fclose(fileOut);
    printf("Data has been sent successfully, please run receive file... "); 
}

int main() {
    // Data source
    char fileinput[] = { "../data/1.txt" };
    // Data destination
    char fileoutput[] = { "../data/2.txt" };
    // Start send data
    start_send(fileinput, fileoutput);
    return 0;
}
