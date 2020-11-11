#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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


///////////////////////网络层-接受-START////////////////////////////////
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

unsigned short extendl_8bit(unsigned int bit_content,int bit_offset){
  bit_content=bit_content<<bit_offset;
  unsigned char res=0b0; //16 bit
  res+=bit_content;
  return res;
}

unsigned short extendr_8bit(unsigned int bit_content,int bit_offset){
  bit_content=bit_content>>bit_offset;
  unsigned char res=0b0; //16 bit
  res+=bit_content;
  return res;
}

// CheckSum
int HeaderGetCheckSum(IP_Packet &ip_packet) {
  return
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

  extendl_16bit(ip_packet.IPv4_HeaderCheckSum,0)+

  extendl_16bit(ip_packet.IPv4_SourceAddr,0)+ //低16bit
  extendr_16bit(ip_packet.IPv4_SourceAddr,16)+

  extendl_16bit(ip_packet.IPv4_DesAddr,0)+ //低16bit
  extendr_16bit(ip_packet.IPv4_DesAddr,16);
}

void PrintBinary(const int argc,int bit_begin,int bit_end){
    for (int i=bit_begin;i>=bit_end;i--)//高位到低位输出
    {
       int a;
       a=0x01&argc>>i;
       printf("%d",a);
    }
}

void network_layer_receriver(unsigned char* payload,int len){
    //IPv4_Version 
    unsigned char IPv4_Version;
    memcpy(&IPv4_Version,&payload[0],1);
    printf("IPv4_Version: ");
    PrintBinary((int)IPv4_Version,7,4);
    printf("\n");

    //IPv4_IHL
    unsigned char IPv4_IHL;
    memcpy(&IPv4_IHL,&payload[0],1);
    PrintBinary((int)IPv4_Version,3,0); // 0 byte
    printf("\n\n");

    //IPv4_TOS
    unsigned char IPv4_TOS;
    memcpy(&IPv4_TOS,&payload[1],1);
    PrintBinary((int)IPv4_TOS,7,0); // 1 byte
    printf("\n\n");
    
    //IPv4_TotalLength
    unsigned short IPv4_TotalLength;
    memcpy(&IPv4_TotalLength,&payload[2],2);
    PrintBinary((int)IPv4_TotalLength,15,0);  // 2,3 byte
    printf("\n\n");
    
    //IPv4_Identification
    unsigned short IPv4_Identification;
    memcpy(&IPv4_Identification,&payload[4],2);
    PrintBinary((int)IPv4_Identification,15,0);  // 4,5 byte
    printf("\n\n");
    
    //IPv4_NoFunc
    unsigned short IPv4_NoFunc;
    memcpy(&IPv4_NoFunc,&payload[6],2);
    PrintBinary((int)IPv4_NoFunc,15,15);  // 6,7 byte
    printf("\n\n");
    
    //IPv4_DF
    unsigned short IPv4_DF;
    memcpy(&IPv4_DF,&payload[6],2);
    PrintBinary((int)IPv4_DF,14,14);  // 6,7 byte
    printf("\n\n");
    
    //IPv4_MF
    unsigned short IPv4_MF;
    memcpy(&IPv4_MF,&payload[6],2);
    PrintBinary((int)IPv4_MF,13,13);  // 6,7 byte
    printf("\n\n");
    
    //IPv4_FragmentOffset
    unsigned short IPv4_FragmentOffset;
    memcpy(&IPv4_FragmentOffset,&payload[6],2);
    PrintBinary((int)IPv4_FragmentOffset,12,0);  // 6,7 byte
    printf("\n\n");
    
    //IPv4_TimeTolive
    unsigned char IPv4_TimeTolive;
    memcpy(&IPv4_TimeTolive,&payload[8],1);
    PrintBinary((int)IPv4_TimeTolive,7,0);  // 8 byte
    printf("\n\n");
    
    //IPv4_Protocol
    unsigned char IPv4_Protocol;
    memcpy(&IPv4_Protocol,&payload[9],1);
    PrintBinary((int)IPv4_Protocol,7,0);  // 9 byte
    printf("\n\n");
    
    //IPv4_HeaderCheckSum
    unsigned short IPv4_HeaderCheckSum;
    memcpy(&IPv4_HeaderCheckSum,&payload[10],2);
    PrintBinary((int)IPv4_HeaderCheckSum,15,0);  // 10,11 byte
    printf("\n\n");
    
    //IPv4_SourceAddr
    unsigned int IPv4_SourceAddr;
    memcpy(&IPv4_SourceAddr,&payload[12],4);
    PrintBinary((int)IPv4_SourceAddr,31,0);  // 12,13,14,15 byte
    printf("\n\n");
    
    //IPv4_DesAddr
    unsigned int IPv4_DesAddr;
    memcpy(&IPv4_DesAddr,&payload[16],4);
    PrintBinary((int)IPv4_DesAddr,31,0);  // 16,17,18,19 byte
    printf("\n\n");
    
    //IPv4_Option
    int Option_Len=(int)IPv4_IHL-5;
    unsigned char IPv4_Option[40];  //最多40个Byte
    memcpy(&IPv4_Option,&payload[20],Option_Len);
    for(int i=0;i<Option_Len;++i){
        PrintBinary((int)IPv4_Option[i],7,0);  // 16,17,18,19 byte
    }
    printf("\n\n");
    
    //IPv4_Data
    int Data_Len=(int)IPv4_TotalLength-(int)IPv4_IHL-5;
    unsigned char IPv4_Data[1500];  //最多40个Byte
    memcpy(&IPv4_Data,&payload[20+Option_Len],Data_Len);
    for(int i=0;i<Data_Len;++i){
        PrintBinary((int)IPv4_Data[i],7,0);  // 16,17,18,19 byte
    }
    printf("\n\n");
    
}
///////////////////////网络层-接受-END////////////////////////////////


///////////////////////数据链路层-接受-START////////////////////////////////
#define MAXSIZE 1500
#define MINSIZE 46

// SIZE:    6Bytes   6Bytes   2Bytes         46-1500Bytes   4Bytes
// MEANING: DA       SA       ProtocalType   PayLoad        FCS

// Mac Address
typedef unsigned char mac_addr[6];
mac_addr my_mac = { 0x3D,0xE1,0x2D,0x6F,0xE9,0x34 };
//mac_addr my_mac = { 0x00,0x00,0x00,0x00,0x00,0x00 };

unsigned char buffer[65536];

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

        unsigned char payload[1500];
        memcpy(payload, &buffer[14], frame_len-18);
        network_layer_receriver(payload, frame_len-18);
        printf("PayLoad:\n");
        printf("%s\n", payload);
        printf("<--------------------------Frame END--------------------------->\n\n");
        FrameIndex++;
    }
}
///////////////////////数据链路层-接受-END////////////////////////////////


///////////////////////测试-START////////////////////////////////
int  main() {
    char fileinput[] = { "../data/2.txt" };
    // 1. Correct reception
    start_receive(fileinput);
    // 2. Wrong MAC address
    // 3. CRC error
    return 0;
}
///////////////////////测试-END////////////////////////////////
