#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UDP_DATA_MAXSIZE 65527
#define IPV4_DATA_MAXSIZE 1440
#define DATALINK_DATA_MAXSIZE 1500

#define BUFLEN 1518
#define PORT 8200
#define LISTNUM 200

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
    a = argc << (32 - bit_begin - 1);
    a = a >> (32 - bit_begin - 1 + bit_end);
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
        printf("%c", UDP_Data[i]);
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
    DF = GetBinary(IPv4_DF, 14, 14);
    MF = GetBinary(IPv4_MF, 13, 13);
    FragmentOffset = GetBinary(IPv4_FragmentOffset, 12, 0);
    printf("MF= %d\n", MF);
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

int main()
{
    int sockfd, newfd;
    struct sockaddr_in s_addr, c_addr;
    char buf[BUFLEN];
    socklen_t len;
    unsigned int port, listnum;
    fd_set rfds;
    struct timeval tv;
    int retval, maxfd;

    /*建立socket*/
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(errno);
    }
    else
        printf("socket create success!\n");
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(PORT);
    s_addr.sin_addr.s_addr = htons(INADDR_ANY);

    /*把地址和端口帮定到套接字上*/
    if ((bind(sockfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr))) == -1)
    {
        perror("bind");
        exit(errno);
    }
    else
        printf("bind success!\n");
    /*侦听本地端口*/
    if (listen(sockfd, listnum) == -1)
    {
        perror("listen");
        exit(errno);
    }
    else
        printf("the server is listening!\n");
    while (1)
    {
        printf("*****************聊天开始***************\n");
        len = sizeof(struct sockaddr);
        if ((newfd = accept(sockfd, (struct sockaddr *)&c_addr, &len)) == -1)
        {
            perror("accept");
            exit(errno);
        }
        else
            printf("客户端是：%s: %d\n", inet_ntoa(c_addr.sin_addr), ntohs(c_addr.sin_port));
        while (1)
        {
            FD_ZERO(&rfds);
            FD_SET(0, &rfds);
            maxfd = 0;
            FD_SET(newfd, &rfds);
            /*找出文件描述符集合中最大的文件描述符*/
            if (maxfd < newfd)
                maxfd = newfd;
            /*设置超时时间*/
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            /*等待聊天*/
            retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
            if (retval == -1)
            {
                printf("select出错，与该客户端连接的程序将退出\n");
                break;
            }
            else if (retval == 0)
            {
                printf("waiting...\n");
                continue;
            }
            else
            {
                /*用户输入信息了*/
                if (FD_ISSET(0, &rfds))
                {

                    /******发送消息*******/
                    memset(buf, 0, sizeof(buf));
                    /*fgets函数：从流中读取BUFLEN-1个字符*/
                    fgets(buf, BUFLEN, stdin);
                    /*打印发送的消息*/
                    //fputs(buf,stdout);
                    if (!strncasecmp(buf, "quit", 4))
                    {
                        printf("server 请求终止聊天!\n");
                        break;
                    }
                    len = send(newfd, buf, strlen(buf), 0);
                    if (len > 0)
                        printf("\t消息发送成功：%s\n", buf);
                    else
                    {
                        printf("消息发送失败!\n");
                        break;
                    }
                }
                /*客户端发来了消息*/
                if (FD_ISSET(newfd, &rfds))
                {
                    /******接收消息*******/
                    memset(buf, 0, sizeof(buf));
                    /*fgets函数：从流中读取BUFLEN-1个字符*/
                    len = recv(newfd, buf, BUFLEN, 0);
                    if (len > 0)
                    {
                        printf("<--------------------------------------------------------------------------------------------------------------->\n");
                        printf("<--------------------------------------------------------------------------------------------------------------->\n");
                        struct sockaddr_in s_addr_clent;
                        socklen_t len_clent;
                        unsigned int port;
                        char buf_clent[BUFLEN];
                        fd_set rfds_clent;
                        struct timeval tv_clent;
                        int retval_clent, maxfd_clent;

                        int sockfd_clent;
                        /*建立socket*/
                        if ((sockfd_clent = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                        {
                            perror("client socket");
                            exit(errno);
                        }
                        else
                            printf("socket create success!\n");

                        /*设置服务器ip*/
                        memset(&s_addr_clent, 0, sizeof(s_addr_clent));
                        s_addr_clent.sin_family = AF_INET;
                        s_addr_clent.sin_port = htons(PORT);
                        if (inet_aton(argv[1], (struct in_addr *)&s_addr_clent.sin_addr.s_addr_clent) == 0)
                        {
                            perror(argv[1]);
                            exit(errno);
                        }
                        /*开始连接服务器*/
                        if (connect(sockfd_clent, (struct sockaddr *)&s_addr_clent, sizeof(struct sockaddr)) == -1)
                        {
                            perror("connect");
                            exit(errno);
                        }
                        else
                            printf("conncet success!\n");

                        FD_ZERO(&rfds_clent);
                        FD_SET(0, &rfds_clent);
                        maxfd_clent = 0;
                        FD_SET(sockfd_clent, &rfds_clent);
                        if (maxfd_clent < sockfd_clent)
                            maxfd_clent = sockfd_clent;
                        tv_clent.tv_sec = 10;
                        tv_clent.tv_usec = 0;
                        retval_clent = select(maxfd_clent + 1, &rfds_clent, NULL, NULL, &tv_clent);
                        if (retval_clent == -1)
                        {
                            printf("select出错，客户端程序退出\n");
                            break;
                        }
                        else if (retval_clent == 0)
                        {
                            printf("waiting...\n");
                            continue;
                        }
                        else
                        {
                            int send_len = send(sockfd_clent, (char *)buf, (int)(len), 0);
                            if (send_len > 0)
                                printf("\t消息发送成功：%s\n", buf_clent);
                            else
                            {
                                printf("消息发送失败!\n");
                                break;
                            }
                        }
                        /*关闭连接*/
                        close(sockfd_clent);
                        printf("<--------------------------------------------------------------------------------------------------------------->\n");
                        printf("<--------------------------------------------------------------------------------------------------------------->\n");
                    }
                    else
                    {
                        if (len < 0)
                            printf("接受消息失败！\n");
                        else
                            printf("客户端退出了，聊天终止！\n");
                        break;
                    }
                }
            }
        }
        /*关闭聊天的套接字*/
        close(newfd);
        /*是否退出服务器*/
        printf("服务器是否退出程序：y->是；n->否? ");
        bzero(buf, BUFLEN);
        fgets(buf, BUFLEN, stdin);
        if (!strncasecmp(buf, "y", 1))
        {
            printf("server 退出!\n");
            break;
        }
    }
    /*关闭服务器的套接字*/
    close(sockfd);
    return 0;
}