#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

#include "tools.h"

#pragma once

// SIZE:    6Bytes   6Bytes   2Bytes         46-1500Bytes   4Bytes
// MEANING: DA       SA       ProtocalType   PayLoad        FCS

// Mac Address
typedef unsigned char mac_addr[6];

// CRC checker
unsigned int crc32(unsigned char* data, int len);

// Merge data to form frames
unsigned short make_frame(mac_addr* dst, mac_addr* src, unsigned short protocol, unsigned char* payload, int payloadlen, unsigned char* result);

// Ready to send a frame
void send_frame(unsigned char* frame_data, unsigned short len, FILE* file);

// Start send
void datalink_layer_send(unsigned char* buf,int len);