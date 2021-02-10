#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <list>
#include <string>
#include "radiotap-protocol.h"
#include "dot11-protocol.h"

void usage();

int main(int argc, char* argv[]) {
	// check syntax
	if (argc != 3) {
		usage();
		return -1;
	}

	char *dev = argv[1];

	// open my network interface
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Error: could not open device %s. (%s)\n", dev, errbuf);
		return -1;
	}

	unsigned char payload[1024] = {};
	size_t payload_len = 0;

	std::list<std::string> ssid_list;
	std::list<std::string>::iterator it;

	{ // Open file
		FILE *f = fopen(argv[2], "rt");

		if (f == NULL) {
			fprintf(stderr, "Error: could not open file %s.\n", argv[2]);
			return -1;
		}

		char ssid[256] = "";

		while (fgets(ssid, 256, f) != NULL) {
			//printf("%s\n", ssid);
			ssid[strcspn(ssid, "\n")] = '\0';
			ssid_list.push_back(ssid);
		}

		fclose(f);
	}

	it = ssid_list.begin();

	while (true) {
		//printf("init radiotap header\n");
		// Input the radiotap packet
		RadioTapHeader rt_header = {
			0x00, // version
			0x00, // pad
			0x0008, // len
			0x00000000  // present
		};

		//printf("payload_len = %u\n", payload_len);
		memcpy(payload + payload_len, (unsigned char *)&rt_header, sizeof(rt_header));
		payload_len += sizeof(rt_header);
		//printf("payload_len = %u\n", payload_len);
		
		// Input 802.11 header common
		Dot11HeaderCommon dot11_header;
		dot11_header.version = 0;
		dot11_header.setTypes(Dot11Types::BEACON_FRAME);
		dot11_header.flags = 0x00;
		dot11_header.duration = 0x0000;

		memcpy(payload + payload_len, (unsigned char *)&dot11_header, sizeof(dot11_header));
		payload_len += sizeof(dot11_header);
		//printf("payload_len = %u\n", payload_len);

		// Input 802.11 beacon frame
		Dot11Beacon dot11_beacon;
		dot11_beacon.receiver_addr = MacAddr("ff:ff:ff:ff:ff:ff");
		dot11_beacon.transmitter_addr = MacAddr("00:11:22:33:44:55");
		dot11_beacon.bssid = MacAddr("00:11:22:33:44:55");
		dot11_beacon.fragment_num = 0x00;
		dot11_beacon.sequence_num = 0x0000;

		memcpy(payload + payload_len, (unsigned char *)&dot11_beacon, sizeof(dot11_beacon));
		payload_len += sizeof(dot11_beacon);
		//printf("payload_len = %u\n", payload_len);

		// Input 802.11 wireless management frame
		Dot11Management dot11_mgmt;
		dot11_mgmt.timestamp = 0;
		dot11_mgmt.beacon_interval = 0x0064;
		dot11_mgmt.capabilities_info = 0x1501;

		memcpy(payload + payload_len, (unsigned char *)&dot11_mgmt, sizeof(dot11_mgmt));
		payload_len += sizeof(dot11_mgmt);
		//printf("payload_len = %u\n", payload_len);

		// Input tag parameters
		payload[payload_len] = Dot11Management::TagNumber::SSID_PARAMETER_SET;
		payload[payload_len + 1] = it->length();
		payload_len += 2;

		memcpy(payload + payload_len, it->c_str(), it->length());
		payload_len += it->length();
		//printf("payload_len = %u\n", payload_len);

		int res = pcap_sendpacket(handle, payload, payload_len);

        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            break;
        } else {
            //printf("Sent %s packet\n", it->c_str());
        }

		if (++it == ssid_list.end())
			it = ssid_list.begin();

		usleep(102400);

		payload_len = 0;
	}

	pcap_close(handle);

	return 0;
}

void usage()
{
	printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
	printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

