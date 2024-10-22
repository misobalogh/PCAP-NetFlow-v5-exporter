# PCAP-NetFlow-v5-exporter

## TODO:
- [ ] unite style across files
- [ ] check unused includes, functions, variables
- [x] add more comments
- [x] add headers with name and descriptioin
- [ ] remove all outputs to console

## Testing:

sudo tcpdump -i any udp port 9995 -w netflow_capture.pcap
- check in wireshark
- python3 netflowV5hexdump.py





## Bibliography
- https://cplusplus.com/reference/
- https://www.w3schools.com/cpp/cpp_oop.asp
- https://www.ibm.com/docs/en/npi/1.3.0?topic=versions-netflow-v5-formats
- https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
- https://www.tcpdump.org/pcap.html

how to read pcap file in cpp
- https://gist.github.com/voldemur/261b5bc42688b9cf425fbaedc2d5fcbe#file-pcap_reader-cpp

- https://man7.org/linux/man-pages/man3/inet_ntop.3.html
- https://man7.org/linux/man-pages/man3/getaddrinfo.3.html

virtual classes in cpp
- https://www.scaler.com/topics/virtual-base-class-in-cpp/

copy constuctor
- https://www.geeksforgeeks.org/copy-constructor-in-cpp/

- https://www.educative.io/answers/how-to-implement-udp-sockets-in-c