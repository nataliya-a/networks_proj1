#include "cJSON.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

#define IP4_HDRLEN 20     // IPv4 header length
#define UDP_HDRLEN 8      // UDP header length, excludes data
#define DATAGRAM_LEN 4096 // datagram length
#define OPT_SIZE 20       // TCP options size

//* A struct representation of the args passed to receive_from function */
struct receive_from_args
{
    int sock;
    char *buffer;
    size_t buffer_length;
    struct sockaddr_in *dst;
    struct timeval *timestamp;
};

// pseudo header needed for tcp header checksum calculation
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

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

// function to calculate checksum
unsigned short csum(unsigned short *ptr, unsigned nbytes)
{
    register long sum;
    unsigned short oddbyte; // if nbytes is odd
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

// Function to create a SYN packet
void synPacket(struct sockaddr_in *src_ip, struct sockaddr_in *dst_ip, char **packet, int *packet_len)
{
    // datagram to represent the packet
    char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

    // required structs for IP and TCP header
    struct ip *iphdr = (struct ip *)datagram;
    struct tcphdr *tcpheader = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct pseudo_header pheader;

    // IP header configuration
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4; // IPv4
    iphdr->ip_tos = 0;
    iphdr->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + OPT_SIZE; // IP header + TCP header + TCP options
    iphdr->ip_id = htonl(12345);
    iphdr->ip_off = 0;
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_TCP;
    iphdr->ip_sum = 0;
    iphdr->ip_src.s_addr = src_ip->sin_addr.s_addr;
    iphdr->ip_dst.s_addr = dst_ip->sin_addr.s_addr;

    // TCP header configuration
    tcpheader->th_sport = src_ip->sin_port;
    tcpheader->th_dport = dst_ip->sin_port;
    tcpheader->th_seq = htonl(rand() % 4294967295);
    tcpheader->th_ack = htonl(0);
    tcpheader->th_off = 10;           // tcp header size
    tcpheader->th_flags = TH_SYN;     /* initial connection request */
    tcpheader->th_sum = 0;            // correct calculation follows later
    tcpheader->th_win = htonl(65535); // window size
    tcpheader->th_urp = 0;

    // TCP pseudo header for checksum calculation
    pheader.source_address = src_ip->sin_addr.s_addr;
    pheader.dest_address = dst_ip->sin_addr.s_addr;
    pheader.placeholder = 0;
    pheader.protocol = IPPROTO_TCP;
    pheader.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
    // fill pseudo packet
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&pheader, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcpheader, sizeof(struct tcphdr) + OPT_SIZE);

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

    tcpheader->th_sum = csum((unsigned short *)pseudogram, psize);
    iphdr->ip_sum = csum((unsigned short *)datagram, iphdr->ip_len);

    *packet = datagram;
    *packet_len = iphdr->ip_len;
    free(pseudogram);
}

// Function to simultaneously receive a packet in response to the SYN packet sent
void *receive_from(void *args)
{
    struct receive_from_args *rfa = (struct receive_from_args *)args;
    int sock = rfa->sock;
    char *buffer = rfa->buffer;
    size_t buffer_length = rfa->buffer_length;
    struct sockaddr_in *dst = rfa->dst;
    struct timeval *timestamp = rfa->timestamp;

    unsigned short dst_port;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
    const int timeout_seconds = 2;
    const int invalid_socket = -1;
    const int timeout_occured = -1;
    const int min_header_length = sizeof(struct ip) + sizeof(struct tcphdr);

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval timeout = {timeout_seconds, 0};
    int nready = select(sock + 1, &read_fds, NULL, NULL, &timeout);
    if (nready == invalid_socket)
    {
        perror("Timeout cannot be set \r \n");
        exit(EXIT_FAILURE);
    }
    else if (nready == 0)
    {
        printf("Timeout occurred \r \n");
        exit(EXIT_FAILURE);
    }

    int received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
    if (received < 0)
    {
        exit(EXIT_FAILURE);
    }

    // struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
    memcpy(&dst_port, buffer + 22, sizeof(dst_port));

    while (dst_port != dst->sin_port || !(tcph->th_flags & TH_RST))
    {
        nready = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        if (nready == invalid_socket)
        {
            perror("Timeout cannot be set \r \n");
            exit(EXIT_FAILURE);
        }
        else if (nready == 0)
        {
            printf("Timeout occurred \r \n");
            exit(EXIT_FAILURE);
        }

        received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
        if (received < min_header_length)
        {
            continue;
        }
        tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
        memcpy(&dst_port, buffer + 22, sizeof(dst_port));
    }

    if (received < 0)
    {
        perror("Could not receive syn ack packet.\n");
        exit(EXIT_FAILURE);
    }
    gettimeofday(timestamp, NULL);

    return NULL;
}

// Fuction to low entropy UDP packets
void low_entropy_udp(struct sockaddr_in serverAddress, int udp_src_port, int num_udp_packets, int udp_buffer_size, int inter_measurement_time, int ttl)
{

    int UDPsocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (UDPsocketFD < 0)
    {
        printf("Could not create udp socket.\n");
        return;
    }

    // Set Don't Fragment bit.
    int flag = 1;
    int result = setsockopt(UDPsocketFD, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag)); // IP_MTU_DISCOVER helps to set the DF bit.
    if (result < 0)
    {
        printf("Could not set DF bit.\n");
        return;
    }

    int ttl;
    result = setsockopt(UDPsocketFD, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if (result < 0)
    {
        printf("Could not set ttl.\n");
        return;
    }
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
    close(UDPsocketFD);
}

// Function to send high entropy udp packets.
void high_entropy_udp(struct sockaddr_in serverAddress, int udp_src_port, int num_udp_packets, int udp_buffer_size, int ttl)
{

    int UDPsocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (UDPsocketFD < 0)
    {
        printf("Could not create udp socket.\n");
        return;
    }

    // Set Don't Fragment bit.
    int flag = 1;
    int result = setsockopt(UDPsocketFD, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag)); // IP_MTU_DISCOVER helps to set the DF bit.
    if (result < 0)
    {
        printf("Could not set DF bit.\n");
        return;
    }

    // Set the ttl to 255.
    int ttl;
    result = setsockopt(UDPsocketFD, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if (result < 0)
    {
        printf("Could not set ttl.\n");
        return;
    }

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

    // Get the number of udp_buffer_size.
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

    // Get tcp port for head syn.
    int tcp_port_for_head_syn = cJSON_GetObjectItem(json, "tcp_port_for_head_syn")->valueint;
    if (tcp_port_for_head_syn == 0)
    {
        printf("Could not find tcp_port_for_head_syn in json config file.\n");
        return 1;
    }

    // Get tcp port for tail syn.
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

    // Get time to live.
    int ttl = cJSON_GetObjectItem(json, "ttl")->valueint;
    if (ttl == 0)
    {
        printf("Could not find ttl in json config file.\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("socket() error");
        exit(1);
    }

    // Create the udp socket.
    struct sockaddr_in tcp_source_addr;
    tcp_source_addr.sin_family = AF_INET;
    tcp_source_addr.sin_port = htons(7777);                   // random client port
    tcp_source_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // random client ip address

    struct sockaddr_in tcp_head_syn_addr;
    tcp_head_syn_addr.sin_family = AF_INET;
    tcp_head_syn_addr.sin_port = htons(tcp_port_for_head_syn);
    tcp_head_syn_addr.sin_addr.s_addr = inet_addr(serverIPAddress); // server ip address

    struct timeval low_entropy_head_timestamp;

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

    char recv_buffer[DATAGRAM_LEN];

    pthread_t low_entropy_head;

    struct receive_from_args low_entropy_head_args;
    low_entropy_head_args.sock = sock;
    low_entropy_head_args.buffer = recv_buffer;
    low_entropy_head_args.buffer_length = sizeof(recv_buffer);
    low_entropy_head_args.dst = &tcp_source_addr;
    low_entropy_head_args.timestamp = &low_entropy_head_timestamp;

    pthread_create(&low_entropy_head, NULL, receive_from, &low_entropy_head_args);

    low_entropy_udp(tcp_head_syn_addr, udp_src_port, num_udp_packets, udp_buffer_size, inter_measurement_time, ttl);

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

    pthread_t low_entropy_tail;

    struct receive_from_args low_entropy_tail_args;
    low_entropy_tail_args.sock = sock;
    low_entropy_tail_args.buffer = recv_buffer;
    low_entropy_tail_args.buffer_length = sizeof(recv_buffer);
    low_entropy_tail_args.dst = &tcp_source_addr;
    low_entropy_tail_args.timestamp = &low_entropy_tail_timestamp;

    pthread_create(&low_entropy_tail, NULL, receive_from, &low_entropy_tail_args);

    pthread_join(low_entropy_head, NULL);
    pthread_join(low_entropy_tail, NULL);

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

    memset(recv_buffer, 0, sizeof(recv_buffer));

    pthread_t high_entropy_head;

    struct receive_from_args high_entropy_head_args;
    high_entropy_head_args.sock = sock;
    high_entropy_head_args.buffer = recv_buffer;
    high_entropy_head_args.buffer_length = sizeof(recv_buffer);
    high_entropy_head_args.dst = &tcp_source_addr;
    high_entropy_head_args.timestamp = &high_entropy_head_timestamp;

    pthread_create(&high_entropy_head, NULL, receive_from, &high_entropy_head_args);

    // send udp high entropy packets on the same socket
    high_entropy_udp(tcp_head_syn_addr, udp_src_port, num_udp_packets, udp_buffer_size, ttl);

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
    memset(recv_buffer, 0, sizeof(recv_buffer));

    pthread_t high_entropy_tail;

    struct receive_from_args high_entropy_tail_args;
    high_entropy_tail_args.sock = sock;
    high_entropy_tail_args.buffer = recv_buffer;
    high_entropy_tail_args.buffer_length = sizeof(recv_buffer);
    high_entropy_tail_args.dst = &tcp_source_addr;
    high_entropy_tail_args.timestamp = &high_entropy_tail_timestamp;

    pthread_create(&high_entropy_tail, NULL, receive_from, &high_entropy_tail_args);

    pthread_join(high_entropy_head, NULL);
    pthread_join(high_entropy_tail, NULL);

    // calculate time difference low entropy head and tail
    long low_entropy_head_tail_time_diff = (low_entropy_tail_timestamp.tv_sec - low_entropy_head_timestamp.tv_sec) * 1000000 + (low_entropy_tail_timestamp.tv_usec - low_entropy_head_timestamp.tv_usec);

    // calculate time difference high entropy head and tail
    long high_entropy_head_tail_time_diff = (high_entropy_tail_timestamp.tv_sec - high_entropy_head_timestamp.tv_sec) * 1000000 + (high_entropy_tail_timestamp.tv_usec - high_entropy_head_timestamp.tv_usec);

    // calculate time difference
    long time_diff = high_entropy_head_tail_time_diff - low_entropy_head_tail_time_diff;

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
