#ifndef __ARGPARSER_H__
#define __ARGPARSER_H__

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#define VERSION "0.9"

/*
 * Cmdline options
 */
struct options_t {
    char *victim_ip;          // victim ip address
    char *victim_mac;         // victim mac address
    char *our_ip;             // our ip address
    char *our_mac;            // our mac address
    char *device;             // interface
    int sleep_time;           // sleep time in microseconds
    int list_devices;         // list all available network devices
    int no_cksum;             // disable packet checksum
    int no_size;              // disable packet size
    int verbosity;            // verbosity level
    int print_dis;            // enable disassembling and pretty printing
} options;

/*
 * Program usage template
 */
const char usage_template[] =
    "PortStealer " VERSION " [MitM tool for ethernet LANs]\n"
    "written by: BUG L'Aquila, Emanuele Acri <crossbower@gmail.com>\n\n"
    "Usage:\n"
    "   portstealer <options> victim_ip victim_mac our_ip our_mac\n"
    "\nOptions:\n"
    "  -i <device> network device to use\n"
    "  -t <time> sleep time in microseconds (default 100000)\n"
    "  -v increment verbosity\n"
    "  -l list all available network devices\n"
    "\nInjection options:\n"
    "  -C disable automatic packet checksum\n"
    "  -S disable automatic packet size\n"
    "\nPretty printing and disassembling options:\n"
    "  -D enable disassembling (pretty printing) of packets\n"
    "\nOther options:\n"
    "  -h help screen\n";

/*
 * Program usage
 */
void usage(FILE *out, const char *error)
{
    fputs(usage_template, out);

    if(error)
        fprintf(out, "\n%s\n", error);
    

    exit(1);
}

/*
 * Parser for command line options
 * See getopt(3)...
 */
int parseopt(int argc, char **argv)
{
    char *c=NULL, *x=NULL;
    char ch;
    
    // cleaning
    memset(&options, 0, sizeof(options));
    
    // default options
    options.sleep_time = 100000;
    
    const char *shortopt = "i:t:vlCSDh"; // short options
    
    while ((ch = getopt (argc, argv, shortopt)) != -1) {
        switch (ch) {
        
            case 'i': // interface
                options.device = optarg;
                break;

            case 't': // sleep time in microseconds
                options.sleep_time = atoi(optarg);
                break;

            case 'v': // increment verbosity
                options.verbosity++;
                break;

            case 'l': // list devices
                options.list_devices = 1;
                break;

            case 'C': // disable packet checksum
                options.no_cksum = 1;
                break;

            case 'S': // disable packet size
                options.no_size = 1;
                break;

            case 'D': // enable disassembling and pretty printing
                options.print_dis = 1;
                break;  
            
            case 'h': //help
                usage(stdout, NULL);

            case '?':
            default:
                usage(stderr, NULL);
        }
    }

    // get victim mac address
    if(optind < argc) {
	options.victim_ip = argv[optind];
    } else {
	usage(stderr, "Error: victim IP address not specified.");
    }

    // get victim mac address
    if((optind + 1) < argc) {
	options.victim_mac = argv[optind + 1];
    } else {
	usage(stderr, "Error: victim MAC address not specified.");
    }
    
    // get our ip address
    if((optind + 2) < argc) {
	options.our_ip = argv[optind + 2];
    } else {
	usage(stderr, "Error: our IP address not specified.");
    }
      
    // get our mac address
    if((optind + 3) < argc) {
	options.our_mac = argv[optind + 3];
    } else {
	usage(stderr, "Error: our MAC address not specified.");
    }
    
    return 1;
}

#endif /* __ARGPARSER_H__ */

