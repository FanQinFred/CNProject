#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UDP_DATA_MAXSIZE 65527
#define IPV4_DATA_MAXSIZE 1440
#define DATALINK_DATA_MAXSIZE 1500

///////////////////////工具-START////////////////////////////////
// OpenFile more safe
FILE *OpenFile(char *fileinput)
{
    FILE *file;
    if ((file = fopen(fileinput, "r+")) == NULL)
    {
        printf("%s\n", "File Open Error!");
        exit(0);
    }
    return file;
}

// Tell file frame position
long int ftellSafe(FILE *file)
{
    long int pos;
    if ((pos = ftell(file)) == -1L)
    {
        exit(0);
    }
    return pos;
}

void PrintBinary(const int argc, int bit_begin, int bit_end)
{
    for (int i = bit_begin; i >= bit_end; i--) //高位到低位输出
    {
        int a;
        a = 0x01 & argc >> i;
        printf("%d", a);
    }
}

int GetBinary(const unsigned int argc, int bit_begin, int bit_end)
{
    unsigned int a;
    a=argc<<(32-bit_begin-1);
    a=a>>(32-bit_begin-1+bit_end);
    return a;
}
///////////////////////工具-END////////////////////////////////

///////////////////////传输层-接受-START////////////////////////////////
struct UDP_Packet
{
    // 16 bit
    unsigned short UDP_SRC_PORT;
    // 16 bit
    unsigned short UDP_DES_PORT;
    // 16 Byte
    unsigned short UDP_LEN;
    // 16 Byte
    unsigned short UDP_CHECK_SUM;
    // (26-8)~(1480-8) Byte
    unsigned char UDP_Data[1472];
};

unsigned char UDP_PACKET[UDP_DATA_MAXSIZE + 8];
int UDP_LEN = 0;

void transfer_layer_receriver(unsigned char *UDP_DATA, int len)
{
    printf("UDP Combined Length: %d\n", UDP_LEN);
    //UDP_SRC_PORT
    unsigned short UDP_SRC_PORT;
    memcpy(&UDP_SRC_PORT, &UDP_DATA[0], 2);
    printf("UDP_SRC_PORT: ");
    PrintBinary((int)UDP_SRC_PORT, 15, 0);
    printf("\n");

    //UDP_DES_PORT
    unsigned short UDP_DES_PORT;
    memcpy(&UDP_DES_PORT, &UDP_DATA[2], 2);
    printf("UDP_DES_PORT: ");
    PrintBinary((int)UDP_DES_PORT, 15, 0);
    printf("\n");

    //UDP_LEN
    unsigned short UDP_LEN;
    memcpy(&UDP_LEN, &UDP_DATA[4], 2);
    printf("UDP_LEN: ");
    PrintBinary((int)UDP_LEN, 15, 0);
    printf("\n");

    //UDP_CHECK_SUM
    unsigned short UDP_CHECK_SUM;
    memcpy(&UDP_CHECK_SUM, &UDP_DATA[6], 2);
    printf("UDP_CHECK_SUM: ");
    PrintBinary((int)UDP_CHECK_SUM, 15, 0);
    printf("\n");

    //UDP_Data
    int Data_Len = (int)UDP_LEN - 8;
    unsigned char UDP_Data[65535];
    memcpy(&UDP_Data, &UDP_DATA[8], Data_Len);

    //暂时不打印UDP_Data
    // printf("UDP_Data: ");
    // for (int i = 0; i < Data_Len; ++i)
    // {
    //     PrintBinary((int)UDP_Data[i], 7, 0); // 16,17,18,19 byte
    // }
    // printf("\n");
    printf("UDP_Data: ");
    for (int i = 0; i < Data_Len; ++i)
    {
        printf("%c",UDP_Data[i]);
    }
    printf("\n");
}
///////////////////////传输层-接受-END////////////////////////////////

///////////////////////网络层-接受-START////////////////////////////////
#define DATA_MAXSIZE 1440 //字节
#define DATA_MINSIZE 26   //字节

struct IP_Packet
{
    // 4 bit
    unsigned int IPv4_Version : 4;
    // 4 bit
    unsigned int IPv4_IHL : 4;
    // 8 bit
    unsigned int IPv4_TOS : 8;

    // 16 bit
    unsigned int IPv4_TotalLength : 16;

    // 16 bit
    unsigned int IPv4_Identification : 16;

    // 1 bit
    unsigned int IPv4_NoFunc : 1;
    // 1 bit
    unsigned int IPv4_DF : 1;
    // 1 bit
    unsigned int IPv4_MF : 1;
    // 13 bit
    unsigned int IPv4_FragmentOffset : 13;

    // 8 bit
    unsigned int IPv4_TimeTolive : 8;
    // 8 bit
    unsigned int IPv4_Protocol : 8;

    // 16 bit
    unsigned int IPv4_HeaderCheckSum : 16;

    // 32 bit
    unsigned int IPv4_SourceAddr : 32;

    // 32 bit
    unsigned int IPv4_DesAddr : 32;

    // 40 Byte
    unsigned char IPv4_Option[40];

    // 26~1480 Byte
    unsigned char IPv4_Data[DATA_MAXSIZE];
};

unsigned short extendl_16bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content << bit_offset;
    unsigned short res = 0b0; //16 bit
    res += bit_content;
    return res;
}

unsigned short extendr_16bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content >> bit_offset;
    unsigned short res = 0b0; //16 bit
    res += bit_content;
    return res;
}

unsigned short extendl_8bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content << bit_offset;
    unsigned char res = 0b0; //16 bit
    res += bit_content;
    return res;
}

unsigned short extendr_8bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content >> bit_offset;
    unsigned char res = 0b0; //16 bit
    res += bit_content;
    return res;
}

// CheckSum
int HeaderGetCheckSum(IP_Packet &ip_packet)
{
    return extendl_16bit(ip_packet.IPv4_Version, 12) +
           extendl_16bit(ip_packet.IPv4_IHL, 8) +
           extendl_16bit(ip_packet.IPv4_TOS, 0) +

           extendl_16bit(ip_packet.IPv4_TotalLength, 0) +

           extendl_16bit(ip_packet.IPv4_Identification, 0) +

           extendl_16bit(ip_packet.IPv4_NoFunc, 15) +
           extendl_16bit(ip_packet.IPv4_DF, 14) +
           extendl_16bit(ip_packet.IPv4_MF, 13) +
           extendl_16bit(ip_packet.IPv4_FragmentOffset, 0) +

           extendl_16bit(ip_packet.IPv4_TimeTolive, 8) +
           extendl_16bit(ip_packet.IPv4_Protocol, 0) +

           extendl_16bit(ip_packet.IPv4_HeaderCheckSum, 0) +

           extendl_16bit(ip_packet.IPv4_SourceAddr, 0) + //低16bit
           extendr_16bit(ip_packet.IPv4_SourceAddr, 16) +

           extendl_16bit(ip_packet.IPv4_DesAddr, 0) + //低16bit
           extendr_16bit(ip_packet.IPv4_DesAddr, 16);
}


void network_layer_receriver(unsigned char *payload, int len)
{
    //IPv4_Version
    unsigned char IPv4_Version;
    memcpy(&IPv4_Version, &payload[0], 1);
    printf("IPv4_Version: ");
    PrintBinary((int)IPv4_Version, 7, 4);
    printf("\n");

    //IPv4_IHL
    unsigned char IPv4_IHL;
    memcpy(&IPv4_IHL, &payload[0], 1);
    printf("IPv4_IHL: ");
    //PrintBinary((int)IPv4_Version,3,0); // 0 byte
    PrintBinary((int)IPv4_Version, 7, 0); // 0 byte
    printf("\n");
    IPv4_IHL = IPv4_IHL << 4;
    IPv4_IHL = IPv4_IHL >> 4;

    //IPv4_TOS
    unsigned char IPv4_TOS;
    memcpy(&IPv4_TOS, &payload[1], 1);
    printf("IPv4_TOS: ");
    PrintBinary((int)IPv4_TOS, 7, 0); // 1 byte
    printf("\n");

    //IPv4_TotalLength
    unsigned short IPv4_TotalLength;
    memcpy(&IPv4_TotalLength, &payload[2], 2);
    printf("IPv4_TotalLength: ");
    PrintBinary((int)IPv4_TotalLength, 15, 0); // 2,3 byte
    printf("\n");

    //IPv4_Identification
    unsigned short IPv4_Identification;
    memcpy(&IPv4_Identification, &payload[4], 2);
    printf("IPv4_Identification: ");
    PrintBinary((int)IPv4_Identification, 15, 0); // 4,5 byte
    printf("\n");

    //IPv4_NoFunc
    unsigned short IPv4_NoFunc;
    memcpy(&IPv4_NoFunc, &payload[6], 2);
    printf("IPv4_NoFunc: ");
    PrintBinary((int)IPv4_NoFunc, 15, 15); // 6,7 byte
    printf("\n");

    //IPv4_DF
    unsigned short IPv4_DF;
    memcpy(&IPv4_DF, &payload[6], 2);
    printf("IPv4_DF: ");
    PrintBinary((int)IPv4_DF, 14, 14); // 6,7 byte
    printf("\n");

    //IPv4_MF
    unsigned short IPv4_MF;
    memcpy(&IPv4_MF, &payload[6], 2);
    printf("IPv4_MF: ");
    PrintBinary((int)IPv4_MF, 13, 13); // 6,7 byte
    printf("\n");

    //IPv4_FragmentOffset
    unsigned short IPv4_FragmentOffset;
    memcpy(&IPv4_FragmentOffset, &payload[6], 2);
    printf("IPv4_FragmentOffset: ");
    PrintBinary((int)IPv4_FragmentOffset, 12, 0); // 6,7 byte
    printf("\n");

    //IPv4_TimeTolive
    unsigned char IPv4_TimeTolive;
    memcpy(&IPv4_TimeTolive, &payload[8], 1);
    printf("IPv4_TimeTolive: ");
    PrintBinary((int)IPv4_TimeTolive, 7, 0); // 8 byte
    printf("\n");

    //IPv4_Protocol
    unsigned char IPv4_Protocol;
    memcpy(&IPv4_Protocol, &payload[9], 1);
    printf("IPv4_Protocol: ");
    PrintBinary((int)IPv4_Protocol, 7, 0); // 9 byte
    printf("\n");

    //IPv4_HeaderCheckSum
    unsigned short IPv4_HeaderCheckSum;
    memcpy(&IPv4_HeaderCheckSum, &payload[10], 2);
    printf("IPv4_HeaderCheckSum: ");
    PrintBinary((int)IPv4_HeaderCheckSum, 15, 0); // 10,11 byte
    printf("\n");

    //IPv4_SourceAddr
    unsigned int IPv4_SourceAddr;
    memcpy(&IPv4_SourceAddr, &payload[12], 4);
    printf("IPv4_SourceAddr: ");
    PrintBinary((int)IPv4_SourceAddr, 31, 0); // 12,13,14,15 byte
    printf("\n");

    //IPv4_DesAddr
    unsigned int IPv4_DesAddr;
    memcpy(&IPv4_DesAddr, &payload[16], 4);
    printf("IPv4_DesAddr: ");
    PrintBinary((int)IPv4_DesAddr, 31, 0); // 16,17,18,19 byte
    printf("\n");

    //IPv4_Option
    int Option_Len = (int)IPv4_IHL * 4 - 20;
    unsigned char IPv4_Option[40]; //最多40个Byte
    memcpy(&IPv4_Option, &payload[20], Option_Len);
    printf("IPv4_Option: ");
    for (int i = 0; i < Option_Len; ++i)
    {
        PrintBinary((int)IPv4_Option[i], 7, 0); // 16,17,18,19 byte
    }
    printf("\n");

    //IPv4_Data
    int Data_Len = (int)IPv4_TotalLength - (int)IPv4_IHL - 5;
    unsigned char IPv4_Data[1500]; //最多40个Byte
    memcpy(&IPv4_Data, &payload[20 + Option_Len], Data_Len);

    //开始拼接
    unsigned short DF, MF, FragmentOffset;
    DF = GetBinary(IPv4_DF,14,14);
    MF = GetBinary(IPv4_MF,13,13);
    FragmentOffset = GetBinary(IPv4_FragmentOffset,12,0);
    printf("MF= %d\n",MF);
    if (MF == 1)
    { //后面还有分片
        UDP_LEN += IPV4_DATA_MAXSIZE;
        for (int i = FragmentOffset * IPV4_DATA_MAXSIZE, l = 0; i < ((FragmentOffset + 1) * IPV4_DATA_MAXSIZE - 1); i++, l++)
        {
            UDP_PACKET[i] = IPv4_Data[l];
        }
    }
    else
    { //最后一个分片
        UDP_LEN += Data_Len;
        for (int i = FragmentOffset * IPV4_DATA_MAXSIZE, l = 0; i < (FragmentOffset * IPV4_DATA_MAXSIZE + Data_Len); i++, l++)
        {
            UDP_PACKET[i] = IPv4_Data[l];
        }
    }
    transfer_layer_receriver(UDP_PACKET, UDP_LEN);
    //结束拼接

    //暂时不打印IPv4_Data
    // printf("IPv4_Data: ");
    // for (int i = 0; i < Data_Len; ++i)
    // {
    //     PrintBinary((int)IPv4_Data[i], 7, 0); // 16,17,18,19 byte
    // }
    // printf("\n");
}
///////////////////////网络层-接受-END////////////////////////////////

///////////////////////数据链路层-接受-START////////////////////////////////
#define MAXSIZE 1500
#define MINSIZE 46

// SIZE:    6Bytes   6Bytes   2Bytes         46-1500Bytes   4Bytes
// MEANING: DA       SA       ProtocalType   PayLoad        FCS

// Mac Address
typedef unsigned char mac_addr[6];
mac_addr my_mac = {0x3D, 0xE1, 0x2D, 0x6F, 0xE9, 0x34};
//mac_addr my_mac = { 0x00,0x00,0x00,0x00,0x00,0x00 };

unsigned char buffer[65536];

// Display MAC address
void show_mac_addr(unsigned char m[6])
{
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", m[i]);
        if (i != 5)
            printf(":");
    }
}

void PrintBinary(const char argc)
{
    for (int i = 7; i >= 0; i--) //高位到低位输出
    {
        int a;
        a = 0x01 & argc >> i;
        printf("%d", a);
    }
}

// Display payload
void show_payload(unsigned char *pl, long int len)
{
    for (int i = 0; i < len; i++)
    {
        PrintBinary(pl[i]);
        //printf("%c", pl[i]);
    }
}

// Show protocol type
void show_protocol(unsigned char m[2])
{
    for (int i = 1; i >= 0; i--)
    {
        printf("%02x", m[i]);
    }
}

// CRC checker
unsigned int crc32(unsigned char *data, int len)
{
    unsigned int crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
    {
        crc = crc ^ data[i];
        for (int j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

// Determine whether the MAC address is the same
bool mac_same(unsigned char *dst_mac, unsigned char *my_mac, int mac_len)
{
    for (int i = 0; i < mac_len; i++)
    {
        if (dst_mac[i] != my_mac[i])
        {
            return false;
        }
    }
    return true;
}

// Start accepting frames
void start_receive(char *fileinput)
{
    FILE *fileIn;
    fileIn = OpenFile(fileinput);
    unsigned short frame_len;
    long int FrameIndex = 1;
    // Receive each frame
    while (fread(&frame_len, sizeof(frame_len), 1, fileIn))
    {
        printf("<-----------------------%d Frame Start-------------------------->\n",FrameIndex);
        printf("frame_len: %d\n", frame_len);
        if (frame_len == 0)
            break;
        // Determine the length of the frame so that it can be received at one time
        fread(buffer, sizeof(char), frame_len, fileIn);
        //CRC
        unsigned int crc32_result = crc32(buffer, frame_len - 4);
        unsigned char crc32_result_c[4];
        memcpy(crc32_result_c, &crc32_result, sizeof(crc32_result));
        // Judge whether the CRC check code is consistent
        bool bool_crc_same = crc32_result_c[3] == buffer[frame_len - 1] &&
                             crc32_result_c[2] == buffer[frame_len - 2] &&
                             crc32_result_c[1] == buffer[frame_len - 3] &&
                             crc32_result_c[0] == buffer[frame_len - 4];
        if (!bool_crc_same)
        {
            printf("CRC ERROR\n");
            exit(0);
        }
        //MAC
        unsigned char dst_mac[6];
        memcpy(&dst_mac, &buffer, 6);
        // Judge whether the MAC address is consistent
        bool bool_mac_same = mac_same(dst_mac, my_mac, 6);
        if (!bool_mac_same)
        {
            printf("MAC ERROR\n");
            exit(0);
        }
        printf("The Content of The %ld th Frame is: \n", FrameIndex);
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
        memcpy(payload, &buffer[14], frame_len - 18);
        network_layer_receriver(payload, frame_len - 18);

        //暂时不打印PayLoad
        // printf("PayLoad:\n");
        // show_payload(payload, frame_len - 18);
        // printf("\n");
        // printf("<----------------------- %ld th Frame END ------------------------>\n\n", FrameIndex);
        FrameIndex++;
        printf("<-----------------------%d Frame End-------------------------->\n",FrameIndex);
    }
}
///////////////////////数据链路层-接受-END////////////////////////////////

///////////////////////测试-START////////////////////////////////
int main()
{
    char fileinput[] = {"./data/2.txt"};
    // 1. Correct reception
    start_receive(fileinput);
    // 2. Wrong MAC address
    // 3. CRC error
    return 0;
    // int a = GetBinary(12, 3, 2);
    // printf("a: %d\n",a);
}
///////////////////////测试-END////////////////////////////////
