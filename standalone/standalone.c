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
#define OPT_SIZE 20       // TCP options size

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

unsigned short checksum(const char *buf, unsigned size)
{
    unsigned sum = 0, i;

    /* Accumulate checksum */
    for (i = 0; i < size - 1; i += 2)
    {
        unsigned short word16 = *(unsigned short *)&buf[i];
        sum += word16;
    }

    /* Handle odd-sized case */
    if (size & 1)
    {
        unsigned short word16 = (unsigned char)buf[i];
        sum += word16;
    }

    /* Fold to get the ones-complement result */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* Invert to get the negative in ones-complement arithmetic */
    return ~sum;
}

void synPacket(struct sockaddr_in *src_ip, struct sockaddr_in *dst_ip, char **packet, int *packet_len)
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
        {
            printf("Timeout occured \r \n");
            return -1;
        }

        received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
        if (received < 0)
            break;
        tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
        memcpy(&dst_port, buffer + 22, sizeof(dst_port));
    } while (dst_port != dst->sin_port || !(tcph->th_flags & TH_RST));

    return received;
}

void low_entropy_udp(struct sockaddr_in serverAddress, int udp_src_port, int num_udp_packets, int udp_buffer_size, int inter_measurement_time)
{

    int UDPsocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (UDPsocketFD < 0)
    {
        printf("Could not create udp socket.\n");
        return;
    }

    // Set Don't Fragment bit.
    int flag = 1;
    int result = setsockopt(UDPsocketFD, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));
    if (result < 0)
    {
        printf("Could not set DF bit.\n");
        return;
    }
    printf("DF bit is set.\n");

    // Bind the socket to the client port.
    struct sockaddr_in clientAddress;
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(udp_src_port);
    clientAddress.sin_addr.s_addr = INADDR_ANY;
    if (bind(UDPsocketFD, (struct sockaddr *)&clientAddress, sizeof(clientAddress)) < 0)
    {
        printf("Could not bind socket to client port.\n");
        return;
    }

    // Create the low entropy udp packet.
    char *lowEntropyPacket = malloc(udp_buffer_size + 2);
    memset(lowEntropyPacket, 0x00, udp_buffer_size + 2);

    PacketID packetID = {0, 0};

    // Send the udp packets.
    for (int i = 0; i < num_udp_packets; i++)
    {
        // create the udp packet.
        memcpy(lowEntropyPacket, &packetID, 2);
        memset(lowEntropyPacket + 2, 0x00, udp_buffer_size);

        // Send the udp packet.
        if (sendto(UDPsocketFD, lowEntropyPacket, udp_buffer_size + 2, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            printf("Could not send udp packet.\n");
            return;
        }

        // Increment the packet id.
        incrementPacketID(&packetID);
        bzero(lowEntropyPacket, udp_buffer_size + 2);
    }
    // Sleep for the inter measurement time.
    printf("Sent low entropy udp packets.\n");
    close(UDPsocketFD);
}

void high_entropy_udp(struct sockaddr_in serverAddress, int udp_src_port, int num_udp_packets, int udp_buffer_size)
{

    int UDPsocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (UDPsocketFD < 0)
    {
        printf("Could not create udp socket.\n");
        return;
    }

    // Set Don't Fragment bit.
    int flag = 1;
    int result = setsockopt(UDPsocketFD, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));
    if (result < 0)
    {
        printf("Could not set DF bit.\n");
        return;
    }
    printf("DF bit is set.\n");

    // Bind the socket to the client port.
    struct sockaddr_in clientAddress;
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(udp_src_port);
    clientAddress.sin_addr.s_addr = INADDR_ANY;
    if (bind(UDPsocketFD, (struct sockaddr *)&clientAddress, sizeof(clientAddress)) < 0)
    {
        printf("Could not bind socket to client port.\n");
        return;
    }

    char *highEntropyPacket = malloc(udp_buffer_size);
    // read random_bits into highEntropyPacket buffer
    FILE *fp = fopen("random_bits", "r");
    if (fp == NULL)
    {
        printf("Could not open random_bits.\n");
        return;
    }
    fread(highEntropyPacket, udp_buffer_size, 1, fp);
    fclose(fp);

    PacketID packetID = {0, 0};
    char *udpPacket = malloc(udp_buffer_size + 2);
    memset(udpPacket, 0, udp_buffer_size + 2);

    // Send the udp packets.
    for (int i = 0; i < num_udp_packets; i++)
    {
        // create the udp packet.
        memcpy(udpPacket, &packetID, 2);
        memset(udpPacket + 2, 0x00, udp_buffer_size);

        // Send the udp packet.
        if (sendto(UDPsocketFD, highEntropyPacket, udp_buffer_size + 2, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            printf("Could not send udp packet.\n");
            return;
        }

        // Increment the packet id.
        incrementPacketID(&packetID);
        bzero(udpPacket, udp_buffer_size + 2);
    }
    printf("Sent high entropy udp packets.\n");
    close(UDPsocketFD);
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
    const char *serverIPAddress = cJSON_GetObjectItem(json, "server_ip_address")->valuestring;
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

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
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

    struct timeval low_entropy_head_timestamp;

    // tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
    {
        perror("setsockopt(IP_HDRINCL, 1) failed\n");
        return 1;
    }

    char *packet;
    int packet_len;
    synPacket(&tcp_source_addr, &tcp_head_syn_addr, &packet, &packet_len);

    int sent;
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&tcp_head_syn_addr, sizeof(struct sockaddr))) == -1)
    {
        perror("sendto() failed\n");
        return 1;
    }

    printf("Sent syn packet.\n");

    char recv_buffer[DATAGRAM_LEN];
    int recv = receive_from(sock, &recv_buffer, sizeof(recv_buffer), &tcp_source_addr);
    if (recv < 0)
    {
        perror("Could not receive syn ack packet.\n");
        return 1;
    }
    gettimeofday(&low_entropy_head_timestamp, NULL);
    printf("Received RST packet.\n");

    // send udp low entropy packets on the same socket
    low_entropy_udp(tcp_head_syn_addr, udp_src_port, num_udp_packets, udp_buffer_size, inter_measurement_time);

    // send tail syn packet
    struct timeval low_entropy_tail_timestamp;
    struct sockaddr_in tcp_tail_syn_addr;
    tcp_tail_syn_addr.sin_family = AF_INET;
    tcp_tail_syn_addr.sin_port = htons(tcp_port_for_tail_syn);
    tcp_tail_syn_addr.sin_addr.s_addr = inet_addr(serverIPAddress);

    synPacket(&tcp_source_addr, &tcp_tail_syn_addr, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&tcp_tail_syn_addr, sizeof(struct sockaddr))) == -1)
    {
        perror("sendto() failed\n");
        return 1;
    }
    printf("Sent tail syn packet.\n");

    recv = receive_from(sock, &recv_buffer, sizeof(recv_buffer), &tcp_source_addr);
    if (recv < 0)
    {
        perror("Could not receive tail syn ack packet.\n");
        return 1;
    }
    gettimeofday(&low_entropy_tail_timestamp, NULL);
    printf("Received tail RST packet.\n");

    sleep(inter_measurement_time);

    // send head syn packet
    struct timeval high_entropy_head_timestamp;
    // reset packet with zeros and packet_len
    packet_len = 0;
    memset(packet, 0, sizeof(packet));
    synPacket(&tcp_source_addr, &tcp_head_syn_addr, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&tcp_head_syn_addr, sizeof(struct sockaddr))) == -1)
    {
        perror("sendto() failed\n");
        return 1;
    }

    printf("Sent head syn packet.\n");

    memset(recv_buffer, 0, sizeof(recv_buffer));
    recv = receive_from(sock, &recv_buffer, sizeof(recv_buffer), &tcp_source_addr);
    if (recv < 0)
    {
        perror("Could not receive head RST packet.\n");
        return 1;
    }

    gettimeofday(&high_entropy_head_timestamp, NULL);
    printf("Received head RST packet.\n");

    // send udp high entropy packets on the same socket
    high_entropy_udp(tcp_head_syn_addr, udp_src_port, num_udp_packets, udp_buffer_size);

    // send tail syn packet
    struct timeval high_entropy_tail_timestamp;
    // reset packet with zeros and packet_len
    packet_len = 0;
    memset(packet, 0, sizeof(packet));
    synPacket(&tcp_source_addr, &tcp_tail_syn_addr, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&tcp_tail_syn_addr, sizeof(struct sockaddr))) == -1)
    {
        perror("sendto() failed\n");
        return 1;
    }
    printf("Sent tail syn packet.\n");
    memset(recv_buffer, 0, sizeof(recv_buffer));
    recv = receive_from(sock, &recv_buffer, sizeof(recv_buffer), &tcp_source_addr);
    if (recv < 0)
    {
        perror("Could not receive tail RST packet.\n");
        return 1;
    }
    gettimeofday(&high_entropy_tail_timestamp, NULL);
    printf("Received tail RST packet.\n");

    // calculate time difference low entropy head and tail
    long low_entropy_head_tail_time_diff = (low_entropy_tail_timestamp.tv_sec - low_entropy_head_timestamp.tv_sec) * 1000000 + (low_entropy_tail_timestamp.tv_usec - low_entropy_head_timestamp.tv_usec);
    printf("Low entropy head tail time difference: %ld microseconds (%ld milliseconds) \n", low_entropy_head_tail_time_diff, low_entropy_head_tail_time_diff / 1000);

    // calculate time difference high entropy head and tail
    long high_entropy_head_tail_time_diff = (high_entropy_tail_timestamp.tv_sec - high_entropy_head_timestamp.tv_sec) * 1000000 + (high_entropy_tail_timestamp.tv_usec - high_entropy_head_timestamp.tv_usec);
    printf("High entropy head tail time difference: %ld microseconds (%ld milliseconds) \n", high_entropy_head_tail_time_diff, high_entropy_head_tail_time_diff / 1000);

    long time_diff = high_entropy_head_tail_time_diff - low_entropy_head_tail_time_diff;

    printf("Time difference: %ld microseconds (%ld milliseconds)", time_diff, time_diff / 1000);

    if (time_diff / 1000 > 100)
    {
        printf("Compression detected.\n");
    }
    else
    {
        printf("No compression detected.\n");
    }

    return 0;
}
