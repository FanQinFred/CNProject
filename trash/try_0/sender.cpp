/*
  @函数采用帕斯卡命名法
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

///////////////////////工具-START////////////////////////////////
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
///////////////////////工具-END////////////////////////////////


///////////////////////数据链路层-发送-START////////////////////////////////
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
    fwrite(frame_data, sizeof(char), len, file);
}

// Start send
void datalink_layer_send(unsigned char* buf,int len,FILE* fileOut){
    unsigned char result[1518];
    unsigned short FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, buf, len, result);
    printf("FrameLength: %d\n",FrameLength);
    send_frame(result, FrameLength, fileOut);
}
///////////////////////数据链路层-发送-END////////////////////////////////


///////////////////////网络层-发送-START////////////////////////////////
#define DATA_MAXSIZE 1440  //字节
#define DATA_MINSIZE 26    //字节

struct IP_Packet{
  // 4 bit
  unsigned int IPv4_Version:4;
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

unsigned char extendl_8bit(unsigned int bit_content,int bit_offset){
  bit_content=bit_content<<bit_offset;
  unsigned char res=0b0; //16 bit
  res+=bit_content;
  return res;
}

unsigned char extendr_8bit(unsigned int bit_content,int bit_offset){
  bit_content=bit_content>>bit_offset;
  unsigned char res=0b0; //16 bit
  res+=bit_content;
  return res;
}

// CheckSum
void HeaderSetCheckSum(IP_Packet &ip_packet) {
  ip_packet.IPv4_HeaderCheckSum=

  extendl_16bit(ip_packet.IPv4_Version,12)+
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

// Make Ip packet
unsigned long MakeIpPacket(const IP_Packet ip_packet,unsigned char* buf,unsigned char* IPv4_Option,long IPv4_Option_Len,unsigned char* IPv4_Data,short IPv4_Data_Len){
  //第一个byte
  unsigned char VersionAndIhl=extendl_8bit(ip_packet.IPv4_Version,4)+extendl_8bit(ip_packet.IPv4_IHL,0); //8 bit
  memcpy(buf,&VersionAndIhl,sizeof(VersionAndIhl));
  //第二个byte
  unsigned char IPv4_TOS=extendl_8bit(ip_packet.IPv4_TOS,0); //8 bit
  memcpy(&buf[1],&IPv4_TOS,sizeof(IPv4_TOS));  //1已经被占用
  //第三四个byte
  unsigned short IPv4_TotalLength=5+40+(short)IPv4_Data_Len;//ip_packet.IPv4_TotalLength;
  memcpy(&buf[2],&IPv4_TotalLength,sizeof(IPv4_TotalLength)); //3已经被占用
  //第五六个byte
  unsigned short IPv4_Identification=ip_packet.IPv4_Identification;
  memcpy(&buf[4],&IPv4_Identification,sizeof(IPv4_Identification)); //5已经被占用
  //第7、8个byte
  unsigned short NoFunc_DF_FragmentOffset=extendl_16bit(ip_packet.IPv4_NoFunc,15)+extendl_16bit(ip_packet.IPv4_DF,14)+extendl_16bit(ip_packet.IPv4_MF,13)+extendl_16bit(ip_packet.IPv4_FragmentOffset,0);
  memcpy(&buf[6],&NoFunc_DF_FragmentOffset,sizeof(NoFunc_DF_FragmentOffset)); //7已经被占用
  //第9、10个byte
  //unsigned short TimeTolive_Protocol=extendl_16bit(ip_packet.IPv4_TimeTolive,8)+extendl_16bit(ip_packet.IPv4_Protocol,0);
  unsigned short TimeTolive_Protocol=extendl_16bit(ip_packet.IPv4_Protocol,8)+extendl_16bit(ip_packet.IPv4_TimeTolive,0);
  memcpy(&buf[8],&TimeTolive_Protocol,sizeof(TimeTolive_Protocol)); //9已经被占用
  //11 12
  unsigned short HeaderCheckSum=ip_packet.IPv4_HeaderCheckSum;
  memcpy(&buf[10],&HeaderCheckSum,sizeof(HeaderCheckSum)); //11已经被占用
  //13 14 15 16
  unsigned int SourceAddr=ip_packet.IPv4_SourceAddr;
  memcpy(&buf[12],&SourceAddr,sizeof(SourceAddr)); //15已经被占用
  //17 18 19 20
  unsigned int DesAddr=ip_packet.IPv4_DesAddr;
  memcpy(&buf[16],&DesAddr,sizeof(DesAddr)); //19已经被占用
  // option
  memcpy(&buf[20],IPv4_Option,IPv4_Option_Len);
  // data
  memcpy(&buf[20+IPv4_Option_Len],IPv4_Data,IPv4_Data_Len);
  //返回字节数
  return 20+IPv4_Option_Len+IPv4_Data_Len;
}

void start_send(IP_Packet ip_packet_info, char* fileinput,char* fileoutput) {
    long int i;
    // The position of the last frame
    long int LastFramePos;
    long int PayLoadCount,AllByteCount;
    long int RestByteCount,LackByteCount;
    FILE* fileOut =OpenFile(fileoutput);
    FILE* fileIn  = OpenFile(fileinput);
    fseek(fileIn, 0, SEEK_END);
    AllByteCount = ftellSafe(fileIn);
    PayLoadCount = AllByteCount / DATA_MAXSIZE;
    rewind(fileIn);
    // Split the data of the file, then each data is processed after segmentation
    for (long int j = 0; j <= PayLoadCount; j++) {
        unsigned char IPv4_Data[DATA_MAXSIZE];
        unsigned char buf[DATA_MAXSIZE+60];
        int FrameLength;
        // Not the last frame
        if (j != PayLoadCount) {
            fread(IPv4_Data, sizeof(char), DATA_MAXSIZE, fileIn);
            unsigned long IpPacketLen=MakeIpPacket(ip_packet_info,buf,ip_packet_info.IPv4_Option,40,IPv4_Data,DATA_MAXSIZE);//AddDataToPacket(ip_packet_info,data,DATA_MAXSIZE,buf);
            printf("if-IpPacketLen: %d\n",IpPacketLen);
            datalink_layer_send(buf, IpPacketLen,fileOut);
        }
        else {
            LastFramePos = ftellSafe(fileIn);
            RestByteCount = AllByteCount - PayLoadCount * DATA_MAXSIZE;
            LackByteCount = DATA_MINSIZE - RestByteCount;
            fread(IPv4_Data, sizeof(char), AllByteCount - LastFramePos, fileIn);
            // The frame size is less than 26 bytes
            if (LackByteCount > 0) {
              for (i = 0;i < LackByteCount; i++) {
                IPv4_Data[RestByteCount++] = 0x00;
              }
              unsigned long IpPacketLen=MakeIpPacket(ip_packet_info,buf,ip_packet_info.IPv4_Option,40,IPv4_Data,DATA_MINSIZE);//AddDataToPacket(ip_packet_info,data,DATA_MAXSIZE,buf);
              printf("else-if-IpPacketLen: %d\n",IpPacketLen);
              datalink_layer_send(buf, IpPacketLen,fileOut);
            }
            else {
              unsigned long IpPacketLen=MakeIpPacket(ip_packet_info,buf,ip_packet_info.IPv4_Option,40,IPv4_Data,RestByteCount);//AddDataToPacket(ip_packet_info,data,DATA_MAXSIZE,buf);
              printf("else-else-IpPacketLen: %d\n",IpPacketLen);
              datalink_layer_send(buf, IpPacketLen,fileOut);
            }
        }

    }
    fclose(fileIn);
    fclose(fileOut);
    printf("Data has been sent successfully, please run receive file...\n"); 
}
///////////////////////网络层-发送-END////////////////////////////////


///////////////////////测试-END////////////////////////////////
// Test
int main(){
	struct IP_Packet ip_packet_info={0b0100,0b1111,0b00000000,  //IPv4_Version,IPv4_IHL,IPv4_TOS
                              0b0000000000000000,  //IPv4_TotalLength
                              0b0000000000000000,  //IPv4_Identification
                              0b0,0b0,0b0,0b0000000000000,  //IPv4_NoFunc,IPv4_DF,IPv4_MF,IPv4_FragmentOffset
                              0b01010101,0b10101010,  //IPv4_TimeTolive,IPv4_Protocol
                              0b0000000000000000,  //IPv4_HeaderCheckSum
                              0b11011010010001101111111101100001,  //IPv4_SourceAddr //218.70.255.97
                              0b01110010001101110101111100001110,  //IPv4_DesAddr //114.55.95.14
                              0b0,  //IPv4_Option
                              0b0}; //IPv4_Data

//  unsigned short TimeTolive_Protocol=extendl_16bit(ip_packet.IPv4_TimeTolive,8)+extendl_16bit(ip_packet.IPv4_Protocol,0);
//  memcpy(&buf[8],&TimeTolive_Protocol,sizeof(TimeTolive_Protocol)); //9已经被占用

	HeaderSetCheckSum(ip_packet_info);
  printf("IPv4_HeaderCheckSum: "); 
  PrintBinary(ip_packet_info.IPv4_HeaderCheckSum);
  printf("\n");
  // Data source
  char fileinput[] = { "./data/1.txt" };
  char fileoutput[] = { "./data/2.txt" };
  // Data destination
  start_send(ip_packet_info, fileinput,fileoutput);
}
///////////////////////测试-END////////////////////////////////
