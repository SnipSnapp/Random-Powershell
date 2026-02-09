#Take a PCAP without installing some stupid 3rd party program
#Fill out the portions in brackets manually.
pktmon start --etw --pkt-size 0 -f <FILENAME> -m multi-file -c

#<COMMANDS that do some network thing>

pktmon stop

pktmon pcapng <FILENAME FROM ABOVE> -o <WhATEVERYOUWANTPCAPNAMETObE>.pcapng
