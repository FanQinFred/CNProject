/*
  @函数采用帕斯卡命名法
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

// 数据链路层S
// Mac Address
typedef unsigned char mac_addr[6];
mac_addr DesMacAddr = { 0x3D,0xE1,0x2D,0x6F,0xE9,0x34 };
mac_addr SrcMacAddr = { 0x34,0xE1,0x2D,0x6F,0xE9,0x3D };

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

void datalink_layer_send(unsigned char* buf,int len){

}
// 数据链路层E


#define DATA_MAXSIZE 1440  //字节
#define DATA_MINSIZE 26    //字节

struct IP_Packet{
  // 4 bit
  unsigned int IPv4_version:4;
  // 4 bit
  unsigned int IPv4_IHL:4;
  // 8 bit
  unsigned int IPv4_TOS:8;

  // 16 bit
  unsigned int IPv4_TotalLength:16;

  // 16 bit
  unsigned int IPv4_Identification:16;

  // 1 bit
  unsigned int IPv4_NoFunc:1;
  // 1 bit
  unsigned int IPv4_DF:1;
  // 1 bit
  unsigned int IPv4_MF:1;
  // 13 bit
  unsigned int IPv4_FragmentOffset:13;

  // 8 bit
  unsigned int IPv4_TimeTolive:8;
  // 8 bit
  unsigned int IPv4_Protocol:8;

  // 16 bit
  unsigned int IPv4_HeaderCheckSum:16;

  // 32 bit
  unsigned int IPv4_SourceAddr:32;

  // 32 bit
  unsigned int IPv4_DesAddr:32;

  // 40 Byte
  unsigned char IPv4_Option[40];

  // 26~1480 Byte
  unsigned char IPv4_Data[DATA_MAXSIZE];
};

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

void PrintBinary(const int argc){
    for (int i=15;i>=0;i--)//高位到低位输出
    {
       int a;
       a=0x01&argc>>i;
       printf("%d",a);
    }
}

unsigned short extendl_16bit(unsigned int bit_content,int bit_offset){
  bit_content=bit_content<<bit_offset;
  unsigned short res=0b0; //16 bit
  res+=bit_content;
  return res;
}

unsigned short extendr_16bit(unsigned int bit_content,int bit_offset){
  bit_content=bit_content>>bit_offset;
  unsigned short res=0b0; //16 bit
  res+=bit_content;
  return res;
}

// CheckSum
void HeaderSetCheckSum(IP_Packet &ip_packet) {
  ip_packet.IPv4_HeaderCheckSum=

  extendl_16bit(ip_packet.IPv4_version,12)+
  extendl_16bit(ip_packet.IPv4_IHL,8)+
  extendl_16bit(ip_packet.IPv4_TOS,0)+

  extendl_16bit(ip_packet.IPv4_TotalLength,0)+

  extendl_16bit(ip_packet.IPv4_Identification,0)+

  extendl_16bit(ip_packet.IPv4_NoFunc,15)+
  extendl_16bit(ip_packet.IPv4_DF,14)+
  extendl_16bit(ip_packet.IPv4_MF,13)+
  extendl_16bit(ip_packet.IPv4_FragmentOffset,0)+

  extendl_16bit(ip_packet.IPv4_TimeTolive,8)+
  extendl_16bit(ip_packet.IPv4_Protocol,0)+

  extendl_16bit(ip_packet.IPv4_SourceAddr,0)+ //低16bit
  extendr_16bit(ip_packet.IPv4_SourceAddr,16)+

  extendl_16bit(ip_packet.IPv4_DesAddr,0)+ //低16bit
  extendr_16bit(ip_packet.IPv4_DesAddr,16);
}

// Add data to IP packet
unsigned int AddDataToPacket(IP_Packet &ip_packet,unsigned char *data, long int len,unsigned char* buf){
  memcpy(ip_packet.IPv4_Data,data,len);
  
  return 60+len;
}

// Make Ip packet
void MakeIpPacket(){

}

void start_send(IP_Packet ip_packet_info, char* fileinput, char* fileoutput) {
    long int i;
    fileIn  = OpenFile(fileinput);
    fileOut = OpenFile(fileoutput);
    fseek(fileIn, 0, SEEK_END);
    AllByteCount = ftellSafe(fileIn);
    PayLoadCount = AllByteCount / 1500;
    rewind(fileIn);
    // Split the data of the file, then each data is processed after segmentation
    for (long int j = 0; j <= PayLoadCount; j++) {
        unsigned char data[DATA_MAXSIZE];
        unsigned char buf[1536];
        int FrameLength;
        // Not the last frame
        if (j != PayLoadCount) {
            fread(data, sizeof(char), DATA_MAXSIZE, fileIn);
            unsigned int IpPacketLen=AddDataToPacket(ip_packet_info,data,DATA_MAXSIZE,buf);
            datalink_layer_send(buf, IpPacketLen);
        }
        else {
            LastFramePos = ftellSafe(fileIn);
            RestByteCount = AllByteCount - PayLoadCount * 1500;
            LackByteCount = DATA_MINSIZE - RestByteCount;
            fread(data, sizeof(char), AllByteCount - LastFramePos, fileIn);
            // The frame size is less than 46 bytes
            if (LackByteCount > 0) {
              for (i = 0;i < LackByteCount; i++) {
                data[RestByteCount++] = 0x00;
              }
              unsigned int IpPacketLen=AddDataToPacket(ip_packet_info,data,DATA_MINSIZE,buf);
              datalink_layer_send(buf, IpPacketLen);
            }
            else {
              unsigned int IpPacketLen=AddDataToPacket(ip_packet_info,data,RestByteCount,buf);
              datalink_layer_send(buf, IpPacketLen);
            }
        }

    }
    fclose(fileIn);
    fclose(fileOut);
    printf("Data has been sent successfully, please run receive file... "); 
}

// Test
int main(){
	struct IP_Packet ip_packet={0b0100,0b0101,0b00000000,  //IPv4_version,IPv4_IHL,IPv4_TOS
                              0b0000000000000000,  //IPv4_TotalLength
                              0b0000000000000000,  //IPv4_Identification
                              0b0,0b0,0b0,0b0000000000000,  //IPv4_NoFunc,IPv4_DF,IPv4_MF,IPv4_FragmentOffset
                              0b11111111,0b00000000,  //IPv4_TimeTolive,IPv4_Protocol
                              0b0000000000000000,  //IPv4_HeaderCheckSum
                              0b11011010010001101111111101100001,  //IPv4_SourceAddr //218.70.255.97
                              0b01110010001101110101111100001110,  //IPv4_DesAddr //114.55.95.14
                              0b0,  //IPv4_Option
                              0b0}; //IPv4_Data
	HeaderSetCheckSum(ip_packet);
  PrintBinary(ip_packet.IPv4_HeaderCheckSum);
  //printf("%s",ip_packet.IPv4_HeaderCheckSum);  //输出
}