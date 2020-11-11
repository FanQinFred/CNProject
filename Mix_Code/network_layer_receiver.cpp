#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    for (int i=bit_begin-1;i>=bit_end;i--)//高位到低位输出
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
    PrintBinary((int)IPv4_Version,7,4);

    //IPv4_IHL
    unsigned char IPv4_IHL;
    memcpy(&IPv4_IHL,&payload[0],1);
    PrintBinary((int)IPv4_Version,3,1); // 0 byte

    //IPv4_TOS
    unsigned char IPv4_TOS;
    memcpy(&IPv4_TOS,&payload[1],1);
    PrintBinary((int)IPv4_TOS,7,0); // 1 byte

    //IPv4_TotalLength
    unsigned short IPv4_TotalLength;
    memcpy(&IPv4_TotalLength,&payload[2],2);
    PrintBinary((int)IPv4_TotalLength,15,0);  // 2,3 byte

    //IPv4_Identification
    unsigned short IPv4_Identification;
    memcpy(&IPv4_Identification,&payload[4],2);
    PrintBinary((int)IPv4_Identification,15,0);  // 4,5 byte

    //IPv4_NoFunc
    unsigned short IPv4_NoFunc;
    memcpy(&IPv4_NoFunc,&payload[6],2);
    PrintBinary((int)IPv4_NoFunc,15,15);  // 6,7 byte

    //IPv4_DF
    unsigned short IPv4_DF;
    memcpy(&IPv4_DF,&payload[6],2);
    PrintBinary((int)IPv4_DF,14,14);  // 6,7 byte

    //IPv4_MF
    unsigned short IPv4_MF;
    memcpy(&IPv4_MF,&payload[6],2);
    PrintBinary((int)IPv4_MF,13,13);  // 6,7 byte

    //IPv4_FragmentOffset
    unsigned short IPv4_FragmentOffset;
    memcpy(&IPv4_FragmentOffset,&payload[6],2);
    PrintBinary((int)IPv4_FragmentOffset,12,0);  // 6,7 byte

    //IPv4_TimeTolive
    unsigned char IPv4_TimeTolive;
    memcpy(&IPv4_TimeTolive,&payload[8],1);
    PrintBinary((int)IPv4_TimeTolive,7,0);  // 8 byte

    //IPv4_Protocol
    unsigned char IPv4_Protocol;
    memcpy(&IPv4_Protocol,&payload[9],1);
    PrintBinary((int)IPv4_Protocol,7,0);  // 9 byte

    //IPv4_HeaderCheckSum
    unsigned short IPv4_HeaderCheckSum;
    memcpy(&IPv4_HeaderCheckSum,&payload[10],2);
    PrintBinary((int)IPv4_HeaderCheckSum,15,0);  // 10,11 byte

    //IPv4_SourceAddr
    unsigned int IPv4_SourceAddr;
    memcpy(&IPv4_SourceAddr,&payload[12],4);
    PrintBinary((int)IPv4_SourceAddr,31,0);  // 12,13,14,15 byte

    //IPv4_DesAddr
    unsigned int IPv4_DesAddr;
    memcpy(&IPv4_DesAddr,&payload[16],4);
    PrintBinary((int)IPv4_DesAddr,31,0);  // 16,17,18,19 byte

    //IPv4_Option
    int Option_Len=(int)IPv4_IHL-5;
    unsigned char IPv4_Option[40];  //最多40个Byte
    memcpy(&IPv4_Option,&payload[20],Option_Len);
    for(int i=0;i<Option_Len;++i){
        PrintBinary((int)IPv4_Option[i],7,0);  // 16,17,18,19 byte
    }
    //IPv4_Data
    int Data_Len=(int)IPv4_TotalLength-(int)IPv4_IHL-5;
    unsigned char IPv4_Data[1500];  //最多40个Byte
    memcpy(&IPv4_Data,&payload[20+Option_Len],Data_Len);
    for(int i=0;i<Data_Len;++i){
        PrintBinary((int)IPv4_Data[i],7,0);  // 16,17,18,19 byte
    }

}