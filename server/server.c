#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>


// Pre probbing phase
char* preProbingPhase(const char *serverIPAddress, int tcp_port)
{
    // Create a socket.
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        printf("Could not create socket.\n");
        return;
    }

    // Set socket options.
    int opt = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(int)); // Allow socket to be reused.

    // Bind the socket.
    struct sockaddr_in serverAddress;
    bzero((char *)&serverAddress, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons((unsigned short)tcp_port);
    if (bind(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        printf("Could not bind socket.\n");
        return;
    }

    // Listen on the socket.
    if (listen(socketFD, 5) < 0)
    {
        printf("Could not listen on socket.\n");
        return;
    }

    // Accept a connection if one is available.
    struct sockaddr_in clientAddress;
    socklen_t clientAddressLength = sizeof(clientAddress);
    int clientSocketFD = accept(socketFD, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (clientSocketFD < 0)
    {
        printf("Could not accept connection.\n");
        return;
    }

    // Receive the data from the client.
    char buffer[1024];
    bzero(buffer, 1024);
    int n = read(clientSocketFD, buffer, 1023);
    if (n < 0)
    {
        printf("Could not read from socket.\n");
        return;
    }


    // Parse the JSON file in the buffer.
    cJSON *json = cJSON_Parse(buffer);
    if (json == NULL)
    {
        printf("Could not parse JSON file.\n");
        return;
    }

    // Get the server ip address.
    const char *clientIPAddress = cJSON_GetObjectItem(json, "server_ip_address")->valuestring;
    int client_tcp_port = cJSON_GetObjectItem(json, "tcp_port")->valueint;
    int number_of_packets = cJSON_GetObjectItem(json, "num_udp_packets")->valueint;
    int udp_buffer_size = cJSON_GetObjectItem(json, "udp_buffer_size")->valueint;
    int client_udp_port = cJSON_GetObjectItem(json, "udp_src_port")->valueint;
    int server_udp_port = cJSON_GetObjectItem(json, "udp_dest_port")->valueint;

    int buffer_size = snprintf(NULL, 0, "server_ip_address: %s \ntcp_port: %d \nnum_udp_packets: %d \nudp_buffer_size: %d \nclient_udp_port: %d \nserver_udp_port: %d \n", clientIPAddress, client_tcp_port, number_of_packets, udp_buffer_size, client_udp_port, server_udp_port);
    // int buffer_size = 1024;
    char* JSONbuffer = malloc(buffer_size + 1);

    bzero(JSONbuffer, buffer_size + 1);
    snprintf(JSONbuffer, buffer_size + 1, "server_ip_address: %s \ntcp_port: %d \nnum_udp_packets: %d \nudp_buffer_size: %d \nclient_udp_port: %d \nserver_udp_port: %d \n", clientIPAddress, client_tcp_port, number_of_packets, udp_buffer_size, client_udp_port, server_udp_port);

    // Close the socket.
    close(clientSocketFD);
    close(socketFD);
    return JSONbuffer;
}

int probing_phase(const char *serverIPAddress, char *JSONbuffer)
{
    // Get the number of udp packets from the JSON buffer.
    char *num_udp_packets_pos = strstr(JSONbuffer, "num_udp_packets:");
    if (num_udp_packets_pos == NULL)
    {
        printf("Error: num_udp_packets: string not found \n");
        return 1;
    }
    num_udp_packets_pos += strlen("num_udp_packets:");
    int num_udp_packets = atoi(num_udp_packets_pos);

    // Get the client udp port from the JSON buffer.
    char* client_udp_port_pos = strstr(JSONbuffer, "client_udp_port:");
    if (client_udp_port_pos == NULL) {
        printf("Error: client_udp_port: string not found \n");
        return 1;
    }
    client_udp_port_pos += strlen("client_udp_port:");
    int client_udp_port = atoi(client_udp_port_pos);

    // Get the server udp port from the JSON buffer.
    char* server_udp_port_pos = strstr(JSONbuffer, "server_udp_port:");
    if (server_udp_port_pos == NULL) {
        printf("Error: server_udp_port: string not found \n");
        return 1;
    }
    server_udp_port_pos += strlen("server_udp_port:");
    int server_udp_port = atoi(server_udp_port_pos);

    // Create a socket.
    int socketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFD < 0)
    {
        printf("Could not create socket.\n");
        return 1;
    }

    // Set socket options.
    int opt = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(int)); // Allow socket to be reused.

    // Bind the socket.
    struct sockaddr_in serverAddress;
    bzero((char *)&serverAddress, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(serverIPAddress);
    serverAddress.sin_port = htons((unsigned short)server_udp_port);
    if (bind(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        printf("Could not bind socket.\n");
        return 1;
    }


    // Receive the UDP packet trains from the client.
    struct sockaddr_in clientAddress;
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY is the client ip address.
    clientAddress.sin_port = htons((unsigned short)client_udp_port); 
    socklen_t clientAddressLength = sizeof(clientAddress);

    struct timeval last_packet_time_for_low_entropy;
    struct timeval last_packet_time_for_high_entropy;

    struct timeval first_packet_time_for_low_entropy;
    struct timeval first_packet_time_for_high_entropy;

    int packet_count = 0;
    char buffer[1024];
    bzero(buffer, 1024);

    struct timeval timeout;
    fd_set readfds;

    printf("Waiting for low entropy packets...\n");
    while (packet_count < num_udp_packets)
    {
        FD_ZERO(&readfds);
        FD_SET(socketFD, &readfds);

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        int rv = select(socketFD + 1, &readfds, NULL, NULL, &timeout); // Wait for 3 seconds for the packet to arrive.
        if (rv == -1)
        {
            printf("Could not select socket.\n");
            return 1;
        }
        else if (rv == 0)
        {
            gettimeofday(&last_packet_time_for_low_entropy, NULL);
            printf("Number of packets received: %d \n", packet_count);
            break;
        }
        else
        {
            int n = recvfrom(socketFD, buffer, 1023, 0, (struct sockaddr *)&clientAddress, &clientAddressLength);
            if (n < 0)
            {
                printf("Could not read from socket.\n");
                return 1;
            }

            if (packet_count == 0)
            {
                gettimeofday(&first_packet_time_for_low_entropy, NULL);
            }
            else if (packet_count == num_udp_packets - 1)
            {
                gettimeofday(&last_packet_time_for_low_entropy, NULL);
            }

            packet_count++;
        }
    }
    printf("Number of packets received: %d \n", packet_count);

    packet_count = 0;
    sleep(6);
    printf("Waiting for high entropy packets...\n");
    while (packet_count < num_udp_packets)
    {
        FD_ZERO(&readfds);
        FD_SET(socketFD, &readfds);

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int rv = select(socketFD + 1, &readfds, NULL, NULL, &timeout); // Wait for 5 seconds for the packet to arrive.
        if (rv == -1)
        {
            printf("Could not select socket.\n");
            return 1;
        }
        else if (rv == 0)
        {
            gettimeofday(&last_packet_time_for_high_entropy, NULL);
            printf("Number of packets received: %d \n", packet_count);
            break;
        }
        else
        {
            int n = recvfrom(socketFD, buffer, 1023, 0, (struct sockaddr *)&clientAddress, &clientAddressLength);
            if (n < 0)
            {
                printf("Could not read from socket.\n");
                return 1;
            }

            if (packet_count == 0)
            {
                gettimeofday(&first_packet_time_for_high_entropy, NULL);
            }
            else if (packet_count == num_udp_packets - 1)
            {
                gettimeofday(&last_packet_time_for_high_entropy, NULL);
            }

            packet_count++;
        }
    }

    // Calculate the time difference.
    // low entropy time difference in microseconds.
    long low_entropy_time_difference = (last_packet_time_for_low_entropy.tv_sec - first_packet_time_for_low_entropy.tv_sec) * 1000000 + (last_packet_time_for_low_entropy.tv_usec - first_packet_time_for_low_entropy.tv_usec);
    printf("Low entropy time difference is %ld microseconds.\n", low_entropy_time_difference);
    long high_entropy_time_difference = (last_packet_time_for_high_entropy.tv_sec - first_packet_time_for_high_entropy.tv_sec) * 1000000 + (last_packet_time_for_high_entropy.tv_usec - first_packet_time_for_high_entropy.tv_usec);
    printf("High entropy time difference is %ld microseconds.\n", high_entropy_time_difference);
    long difference = high_entropy_time_difference - low_entropy_time_difference;

    printf("Time difference is %ld microseconds.\n", difference);

    // Close the socket.
    close(socketFD);

    // convert the time difference to milliseconds.
    difference = difference / 1000;

    printf("Time difference is %ld milliseconds.\n", difference);

    if (difference > 100)
    {
        return 1; // compression detected.
    }
    else
    {
        return 0; // compression not detected.
    }
}

void postProbingPhase(const char *serverIPAddress, int tcp_port, int c)
{
    // Create a socket.
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        printf("Could not create socket.\n");
        return;
    }

    printf("Socket created.\n");

    // Bind the socket.
    struct sockaddr_in serverAddress;
    bzero((char *)&serverAddress, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(tcp_port);
    serverAddress.sin_addr.s_addr = inet_addr(serverIPAddress);

    int optval = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

    if (bind(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        printf("Could not bind socket.\n");
        return;
    }
    printf("Socket bound.\n");

    // Listen for connections.
    listen(socketFD, 5);

    // Accept a connection.
    struct sockaddr_in clientAddress;
    socklen_t clientAddressLength = sizeof(clientAddress);
    int newSocketFD = accept(socketFD, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (newSocketFD < 0)
    {
        printf("Could not accept connection.\n");
        return;
    }

    // Send a message to the client.
    char buffer[1024];
    bzero(buffer, 1024);
    if (c == 0)
    {
        strcpy(buffer, "No compression detected.");
    }
    else
    {
        strcpy(buffer, "Compression detected.");
    }

    int n = send(newSocketFD, buffer, strlen(buffer), 0);
    if (n < 0)
    {
        printf("Could not write to socket.\n");
        return;
    }

    // Close the socket.
    close(newSocketFD);
    close(socketFD);
}

int main(int argc, char *argv[])
{
    // Check the number of arguments.
    if (argc != 2)
    {
        printf("Usage: %s <JSON file>\n", argv[0]);
        return 1;
    }

    printf("Reading JSON file...\n");

    // Read the JSON file.
    FILE *jsonFile = fopen(argv[1], "r");
    if (jsonFile == NULL)
    {
        printf("Could not open JSON file.\n");
        return 1;
    }

    // Get the file size.
    fseek(jsonFile, 0, SEEK_END);
    long fileSize = ftell(jsonFile);
    fseek(jsonFile, 0, SEEK_SET);

    // Read the file.
    char *jsonString = malloc(fileSize + 1);
    fread(jsonString, 1, fileSize, jsonFile);
    fclose(jsonFile);
    jsonString[fileSize] = 0; // Null terminate the string.

    // Parse the JSON file.
    cJSON *json = cJSON_Parse(jsonString);
    if (json == NULL)
    {
        printf("Could not parse JSON file.\n");
        return 1;
    }

    // Get the server ip address.
    const char *serverIPAddress = cJSON_GetObjectItem(json, "server_ip_address")->valuestring;
    if (serverIPAddress == NULL)
    {
        printf("Could not find server_ip_address in JSON file.\n");
        return 1;
    }

    // Get the server tcp port.
    int tcp_port = cJSON_GetObjectItem(json, "tcp_port")->valueint;
    if (tcp_port == 0)
    {
        printf("Could not find tcp_port in JSON file.\n");
        return 1;
    }

    printf("Reading JSON file completed.\n");

    printf("Waiting for connection...\n");
    char *JSONbuffer = preProbingPhase(serverIPAddress, tcp_port);
    printf("Connection established.\n");

    int c = probing_phase(serverIPAddress, JSONbuffer);
    printf("Probing phase completed.\n");

    printf("Establishing connection to the client...\n");
    printf("Connection established.\n");
    postProbingPhase(serverIPAddress, tcp_port, c);
    printf("Post probing phase completed.\n");

    printf("Shutting down...\n");

    free(JSONbuffer);
    return 0;
}