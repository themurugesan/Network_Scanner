import scapy.all as scapy
import argparse

def get_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument("-r","--range",dest="range",help="Use --range To Scan Your")
    options=parser.parse_args()
    if not options.range:
        parser.error("Please Specify An Option")
    else:
        return options
def scan(ip):
    arp_request =scapy.ARP(pdst=ip)
    source_destionation=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final=source_destionation/arp_request
    answered_list=scapy.srp(final,timeout=1,verbose=False)[0]
    # print(answered_list.summary())
    result_list=[]
    for answer in answered_list:
        result_dic={"ip":answer[1].psrc,"mac":answer[1].hwsrc}
        result_list.append(result_dic)
        # print(answer[1].psrc + "\t\t\t\t" +answer[1].hwsrc )

        # print("-----------------------------------------------------------")
    return result_list
def print_results(result_list):
    print("\tIP\t\t\tMAC\n-----------------------------------------------------------")
    for result in result_list:
        print(result["ip"]+"\t\t"+result["mac"])


    # final.show()
    # print(source_destionation)
    # source_destionation.show()

    # arp_request.show()
    #
    # print(arp_request.summary())
    # scapy.ls(scapy.Ether())


options=get_arguments()
result_dir=scan(options.range)
print_results(result_dir)