#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

#define IP4_HDRLEN 20     // IPv4 header length
#define UDP_HDRLEN 8      // UDP header length, excludes data
#define DATAGRAM_LEN 4096 // datagram length
#define OPT_SIZE 20    // TCP options size

// TCP header
// struct tcphdr
// {
//     uint16_t th_sport; // source port
//     uint16_t th_dport; // destination port
//     uint32_t th_seq;   // sequence number
//     uint32_t th_ack;   // acknowledgement number
//     uint8_t th_x2 : 4; // (unused)
//     uint8_t th_off : 4; // data offset
//     uint8_t th_flags;
//     uint16_t th_win; // window
//     uint16_t th_sum; // checksum
//     uint16_t th_urp; // urgent pointer
// };

// IP header
// struct ip
// {
//     uint8_t ihl : 4;
//     uint8_t version : 4;
//     uint8_t tos;
//     uint16_t tot_len;
//     uint16_t id;
//     uint16_t frag_off;
//     uint8_t ttl;
//     uint8_t protocol;
//     uint16_t check;
//     uint32_t saddr;
//     uint32_t daddr;
// };

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// struct udphdr
// {
//     uint16_t uh_sport; // source port
//     uint16_t uh_dport; // destination port
//     uint16_t uh_ulen;  // datagram length
//     uint16_t uh_sum;   // datagram checksum
// };

/** A struct representation of the packet id. */
typedef struct
{
    uint8_t most_sig_bit;
    uint8_t least_sig_bit;
} PacketID;

/** Adds the PacketID by 1*/
void incrementPacketID(PacketID *packetID)
{
    packetID->least_sig_bit += 1;
    if (packetID->least_sig_bit == 0)
    {
        packetID->most_sig_bit += 1;
    }
}

unsigned short checksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2; // 2 bytes at a time for 16 bit checksum
    }
    if (nbytes == 1) // if odd number of bytes
    {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff); // adds upper 16 bits to lower 16 bits
    sum = sum + (sum >> 16);            // add overflow
    answer = (short)~sum;               // ones complement

    return (answer);
}

void synPacket(struct sockaddr_in* src_ip, struct sockaddr_in* dst_ip, char *packet, char *packet_len)
{
    // datagram to represent the packet
    char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

    // required structs for IP and TCP header
    struct ip *iph = (struct ip *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct pseudo_header psh;

    // IP header configuration
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + OPT_SIZE;
    iph->ip_id = htonl(12345); // id of this packet
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0; // correct calculation follows later
    iph->ip_src.s_addr = src_ip->sin_addr.s_addr;
    iph->ip_dst.s_addr = dst_ip->sin_addr.s_addr;

    // TCP header configuration
    tcph->th_sport = src_ip->sin_port;
    tcph->th_dport = dst_ip->sin_port;
    tcph->th_seq = htonl(rand() % 4294967295);
    tcph->th_ack = htonl(0);
    tcph->th_off = 10;           // tcp header size
    tcph->th_flags = TH_SYN;     /* initial connection request */
    tcph->th_sum = 0;            // correct calculation follows later
    tcph->th_win = htonl(65535); // window size
    tcph->th_urp = 0;

    // TCP pseudo header for checksum calculation
    psh.source_address = src_ip->sin_addr.s_addr;
    psh.dest_address = dst_ip->sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
    // fill pseudo packet
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

    // TCP options are only set in the SYN packet
    // ---- set mss ----
    datagram[40] = 0x02;
    datagram[41] = 0x04;
    int16_t mss = htons(48); // mss value
    memcpy(datagram + 42, &mss, sizeof(int16_t));
    // ---- enable SACK ----
    datagram[44] = 0x04;
    datagram[45] = 0x02;
    // do the same for the pseudo header
    pseudogram[32] = 0x02;
    pseudogram[33] = 0x04;
    memcpy(pseudogram + 34, &mss, sizeof(int16_t));
    pseudogram[36] = 0x04;
    pseudogram[37] = 0x02;

    tcph->th_sum = checksum((const char *)pseudogram, psize);
    iph->ip_sum = checksum((const char *)datagram, iph->ip_len);

    *packet = datagram;
    *packet_len = iph->ip_len;
    free(pseudogram);
}

// void udpPacket(char *src_ip, char *dst_ip, char *packet, char *packet_len)
// {
//     int udp_buffer_size = 65536;
//     struct ip iphdr;
//     struct udphdr udphdr;

//     // IP header
//     iphdr.ihl = 5;
//     iphdr.version = 4;
//     iphdr.tos = 0;
//     iphdr.tot_len = htons(IP4_HDRLEN + sizeof(udphdr));
//     iphdr.id = htons(0);
//     iphdr.frag_off = htons(0);
//     iphdr.ttl = 255;
//     iphdr.protocol = IPPROTO_UDP;
//     iphdr.check = 0;
//     iphdr.saddr = inet_addr(src_ip);
//     iphdr.daddr = inet_addr(dst_ip);

//     // UDP header
//     // udphdr.uh_sport = htons(0);
//     // udphdr.uh_dport = htons(0);
//     // udphdr.uh_ulen = htons(sizeof(udphdr));
//     // udphdr.uh_sum = 0;

//     // // Copy the IP header and UDP header into the packet
//     // memcpy(packet, &iphdr, IP4_HDRLEN);
//     // memcpy((packet + IP4_HDRLEN), &udphdr, sizeof(udphdr));

//     // // Total length of the packet
//     // *packet_len = IP4_HDRLEN + sizeof(udphdr);

//     PacketID packetID = {0, 0};

//     // Create the high entropy udp packet.
//     char *highEntropyPacket = malloc(udp_buffer_size);
//     // read random_bits into highEntropyPacket buffer
//     FILE *fp = fopen("random_bits", "r");
//     if (fp == NULL)
//     {
//         printf("Could not open random_bits.\n");
//         return;
//     }
//     fread(highEntropyPacket, udp_buffer_size, 1, fp);
//     fclose(fp);

//     sleep(1);

//     char *udpPacket = malloc(udp_buffer_size + 2);
//     memset(udpPacket, 0, udp_buffer_size + 2);

//     // Send the udp packets.
//     for (int i = 0; i < num_udp_packets; i++)
//     {

//         // create the udp packet.
//         memcpy(udpPacket, &packetID, 2);
//         memset(udpPacket + 2, 0x00, udp_buffer_size);

//         // Send the udp packet.
//         if (sendto(UDPsocketFD, udpPacket, udp_buffer_size + 2, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
//         {
//             printf("Could not send udp packet.\n");
//             return;
//         }

//         incrementPacketID(&packetID);
//         bzero(udpPacket, udp_buffer_size + 2);
//     }
//     // Sleep for the inter measurement time.
//     printf("Sent low entropy udp packets.\n");
//     sleep(inter_measurement_time);
//     printf("Sleeping for %d seconds.\n", inter_measurement_time);
//     // reset the packet id.//
//     packetID = (PacketID){0, 0};

//     for (int i = 0; i < num_udp_packets; i++)
//     {
//         // create the udp packet.
//         memcpy(udpPacket, &packetID, 2);
//         memcpy(udpPacket + 2, highEntropyPacket, udp_buffer_size);

//         // Send the udp packet.
//         if (sendto(UDPsocketFD, udpPacket, udp_buffer_size + 2, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
//         {
//             printf("Could not send udp packet.\n");
//             return;
//         }

//         // Increment the packet id.
//         incrementPacketID(&packetID);
//         bzero(udpPacket, udp_buffer_size + 2);
//     }
//     printf("Sent high entropy udp packets.\n");
// }

int receive_from(int sock, char *buffer, size_t buffer_length, struct sockaddr_in *dst)
{
    unsigned short dst_port;
    int received;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));

    fd_set read_fds;        // set of file descriptors to wait for input on
    int nready;             // number of file descriptors ready for input
    struct timeval timeout; // timeout value
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds); // add socket file descriptor to the set
    timeout.tv_sec = 2;      // set the timeout value to 2 seconds
    timeout.tv_usec = 0;
    do
    {
        nready = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        if (nready == -1)
        {
            perror("Timeout cannot be set \r \n");
            exit(1);
        }
        else if (nready == 0)
            return -1;

        received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
        if (received < 0)
            break;
        tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
        memcpy(&dst_port, buffer + 22, sizeof(dst_port));
    } while (dst_port != dst->sin_port || !(tcph->th_flags & TH_RST));

    return received;
}

int main(int argc, char *argv[])
{
    // Check if the user has entered the correct number of arguments.
    if (argc != 2)
    {
        printf("Need to pass in a json config file.\n");
        return 1;
    }

    // Open the json config file.
    FILE *jsonFile = fopen(argv[1], "r");
    if (jsonFile == NULL)
    {
        printf("Could not open json config file.\n");
        return 1;
    }

    printf("Opened json config file.\n");

    // Read the json config file.
    fseek(jsonFile, 0, SEEK_END);
    long fileSize = ftell(jsonFile);
    fseek(jsonFile, 0, SEEK_SET);
    char *jsonString = malloc(fileSize + 1);
    fread(jsonString, 1, fileSize, jsonFile);
    fclose(jsonFile);
    jsonString[fileSize] = 0; // Null terminate the string.

    // Parse the json config file.
    cJSON *json = cJSON_Parse(jsonString);
    if (json == NULL)
    {
        printf("Could not parse json config file.\n");
        return 1;
    }

    // Get the server ip address.
    char *serverIPAddress = cJSON_GetObjectItem(json, "server_ip_address")->valuestring;
    if (serverIPAddress == NULL)
    {
        printf("Could not find server_ip_address in json config file.\n");
        return 1;
    }

    // Get the server port.
    int udp_dest_port = cJSON_GetObjectItem(json, "udp_dest_port")->valueint;
    if (udp_dest_port == 0)
    {
        printf("Could not find server_port in json config file.\n");
        return 1;
    }

    // Get the client port.
    int udp_src_port = cJSON_GetObjectItem(json, "udp_src_port")->valueint;
    if (udp_src_port == 0)
    {
        printf("Could not find client_port in json config file.\n");
        return 1;
    }

    int udp_buffer_size = cJSON_GetObjectItem(json, "udp_buffer_size")->valueint;
    if (udp_buffer_size == 0)
    {
        printf("Could not find udp_buffer_size in json config file.\n");
        return 1;
    }

    // Get tcp port.
    int tcp_port = cJSON_GetObjectItem(json, "tcp_port")->valueint;
    if (tcp_port == 0)
    {
        printf("Could not find tcp_port in json config file.\n");
        return 1;
    }

    int tcp_port_for_head_syn = cJSON_GetObjectItem(json, "tcp_port_for_head_syn")->valueint;
    if (tcp_port_for_head_syn == 0)
    {
        printf("Could not find tcp_port_for_head_syn in json config file.\n");
        return 1;
    }

    int tcp_port_for_tail_syn = cJSON_GetObjectItem(json, "tcp_port_for_tail_syn")->valueint;
    if (tcp_port_for_tail_syn == 0)
    {
        printf("Could not find tcp_port_for_tail_syn in json config file.\n");
        return 1;
    }

    // Get inter measurement time.
    int inter_measurement_time = cJSON_GetObjectItem(json, "inter_measurement_time")->valueint;
    if (inter_measurement_time == 0)
    {
        printf("Could not find inter_measurement_time in json config file.\n");
        return 1;
    }

    // Get number of udp packets.
    int num_udp_packets = cJSON_GetObjectItem(json, "num_udp_packets")->valueint;
    if (num_udp_packets == 0)
    {
        printf("Could not find num_udp_packets in json config file.\n");
        return 1;
    }

    int ttl = cJSON_GetObjectItem(json, "ttl")->valueint;
    if (ttl == 0)
    {
        printf("Could not find ttl in json config file.\n");
        return 1;
    }

    printf("Read json config file.\n");

    int sock;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket() error");
        exit(1);
    }

    struct sockaddr_in tcp_source_addr;
    tcp_source_addr.sin_family = AF_INET;
    tcp_source_addr.sin_port = htons(12345); // random client port
    tcp_source_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    struct sockaddr_in tcp_head_syn_addr;
    tcp_head_syn_addr.sin_family = AF_INET;
    tcp_head_syn_addr.sin_port = htons(tcp_port_for_head_syn);
    tcp_head_syn_addr.sin_addr.s_addr = inet_addr(serverIPAddress);

    char *packet;
    int packet_len;
    synPacket(&tcp_source_addr, &tcp_head_syn_addr, &packet, &packet_len);

    int sent;
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&tcp_head_syn_addr, sizeof(tcp_head_syn_addr))) < 0)
    {
        printf("Could not send syn packet.\n");
        return 1;
    }

    printf("Sent syn packet.\n");

    char recv_buffer[1024];
    int recv = receive_from(sock, &recv_buffer, sizeof(recv_buffer), &tcp_source_addr);
    if (recv < 0)
    {
        printf("Could not receive syn ack packet.\n");
        return 1;
    }

    printf("Received syn ack packet.\n");


}
