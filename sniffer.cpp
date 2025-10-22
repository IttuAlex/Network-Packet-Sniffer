#include <iostream>
#include <pcap/pcap.h>

using namespace std;


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){

    pcap_dump(user, h, bytes);
    cout << "Packet: " << h->len << " bytes" << endl;
    

}

char *take_interface(){
    pcap_if_t *alldevsp, *d;
    pcap_t *interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *interface_name;
    if(pcap_findalldevs(&alldevsp, errbuf) == -1){
        cerr << "Error" << errbuf << endl;
       
    }
    
    char *source = alldevsp->name;
    
    int i=0;
    while(source[i] != '\0')
        i++;
     
    for(int j=0; j<=i; j++){
        interface_name[i] = source[i];

    }

    cout << "Interface mapping done" << endl;
    
    pcap_freealldevs(alldevsp);

    return interface_name;


}

void packet_capture(int nr_packets){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *interface;
    char *interface_name = take_interface();

        if(interface_name){
        interface = pcap_open_live(interface_name, 65535, 1, 1000, errbuf);
        
    }
    else{
        cerr << "Error" << errbuf << endl;
        
    }

    

    pcap_dumper_t *dumper = pcap_dump_open(interface, "out.pcap");

    pcap_loop(interface, nr_packets, packet_handler, (u_char*)dumper);
    
    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);


    pcap_close(interface);
}

void show_decimal(char *errbuf, int nr_packets){
    
    pcap_t *handle = pcap_open_offline("out.pcap", errbuf);

    const u_char *bytes;
    struct pcap_pkthdr *h;

    int packet = pcap_next_ex(handle, &h, &bytes);

    for(int j = 0; j< nr_packets; j++){

        for(int i = 0; i < h->caplen; i++){
            printf(" %02x", bytes[i]);

        }
        cout << endl;
    }
    pcap_close(handle);


}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    
    
    
    return 0;
}