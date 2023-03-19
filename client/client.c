// #include "cJSON.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <time.h>

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

/** Pre probing phase. */
void preProbingPhase(char *serverIPAddress, int tcp_port, char *jsonString)
{
    // Create a socket.
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        printf("Could not create socket.\n");
        return;
    }

    // Get the server address.
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(tcp_port);
    serverAddress.sin_addr.s_addr = inet_addr(serverIPAddress);

    // Connect to the server.
    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        printf("Could not connect to server.\n");
        return;
    }

    // Send the json config file to the server.
    if (send(socketFD, jsonString, strlen(jsonString), 0) < 0)
    {
        printf("Could not send json config file to server.\n");
        return;
    }

    // Close the socket.
    close(socketFD);
}

/** Probing phase. */
void probingPhase(char *serverIPAddress, int udp_dest_port, int udp_src_port, int udp_buffer_size, int num_udp_packets, int inter_measurement_time)
{
    // Create a socket.
    int UDPsocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (UDPsocketFD < 0)
    {
        printf("Could not create socket.\n");
        return;
    }

    // Get the server address.
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(udp_dest_port);
    serverAddress.sin_addr.s_addr = inet_addr(serverIPAddress);

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

    printf("Socket is bound to client port.\n");

    // Create the packet id.
    PacketID packetID = {0, 0};

    // Create the high entropy udp packet.
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

    sleep(1);

    char *udpPacket = malloc(udp_buffer_size + 2);
    memset(udpPacket, 0, udp_buffer_size + 2);
    // Send the udp packets.
    for (int i = 0; i < num_udp_packets; i++)
    {

        // create the udp packet.
        memcpy(udpPacket, &packetID, 2);
        memset(udpPacket + 2, 0x00, udp_buffer_size);

        // Send the udp packet.
        if (sendto(UDPsocketFD, udpPacket, udp_buffer_size + 2, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            printf("Could not send udp packet.\n");
            return;
        }

        incrementPacketID(&packetID);
        bzero(udpPacket, udp_buffer_size + 2);
    }
    // Sleep for the inter measurement time.
    printf("Sent low entropy udp packets.\n");
    sleep(inter_measurement_time);
    printf("Sleeping for %d seconds.\n", inter_measurement_time);
    // reset the packet id.//
    packetID = (PacketID){0, 0};

    for (int i = 0; i < num_udp_packets; i++)
    {
        // create the udp packet.
        memcpy(udpPacket, &packetID, 2);
        memcpy(udpPacket + 2, highEntropyPacket, udp_buffer_size);

        // Send the udp packet.
        if (sendto(UDPsocketFD, udpPacket, udp_buffer_size + 2, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            printf("Could not send udp packet.\n");
            return;
        }

        // Increment the packet id.
        incrementPacketID(&packetID);
        bzero(udpPacket, udp_buffer_size + 2);
    }
    printf("Sent high entropy udp packets.\n");

    // Close the socket.
    close(UDPsocketFD);
}

void postProbingPhase(char *serverIPAddress, int tcp_dest_port)
{
    // Create a socket.
    int TCPsocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (TCPsocketFD < 0)
    {
        printf("Could not create socket.\n");
        return;
    }

    // Get the server address.
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(tcp_dest_port);
    serverAddress.sin_addr.s_addr = inet_addr(serverIPAddress);

    // Connect to the server.
    if (connect(TCPsocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        printf("Could not connect to server.\n");
        return;
    }

    printf("Connected to server.\n");

    // Read the data sent by server from the socket.
    char buffer[256];
    bzero(buffer, 256);
    if (read(TCPsocketFD, buffer, 255) < 0)
    {
        printf("Could not read from socket.\n");
        return;
    }

    printf("Read from socket.\n");
    // Print the data read from the socket.
    printf("%s\n", buffer);

    // Close the socket.
    close(TCPsocketFD);
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

    // Get tcp port.
    int tcp_port = cJSON_GetObjectItem(json, "tcp_port")->valueint;
    if (tcp_port == 0)
    {
        printf("Could not find tcp_port in json config file.\n");
        return 1;
    }

    // Get upd buffer size.
    int udp_buffer_size = cJSON_GetObjectItem(json, "udp_buffer_size")->valueint;
    if (udp_buffer_size == 0)
    {
        printf("Could not find udp_buffer_size in json config file.\n");
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
    printf("Read json config file.\n");

    printf("Starting pre probing phase.\n");
    preProbingPhase(serverIPAddress, tcp_port, jsonString);
    printf("Pre probing phase complete.\n");

    printf("Starting probing phase.\n");
    probingPhase(serverIPAddress, udp_dest_port, udp_src_port, udp_buffer_size, num_udp_packets, inter_measurement_time);
    printf("Probing phase complete.\n");

    printf("Starting post probing phase.\n");
    postProbingPhase(serverIPAddress, tcp_port);
    printf("Post probing phase complete.\n");

    return 0;
}
