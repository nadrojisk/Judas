import scapy.all as sc

# traffic = sc.sniff(offline='C:\\Users\\C\\Documents\\GitHub\\PythonBackdoor\\assets\\pcap\\specific.pcapng')
# client_ip = ""
# server_ip = ""
# http_exe_start = 0
# exe_start = 0

# #finds the beginning of the http exe request
# for i in range(0, len(traffic)):
#     p = traffic[i]
#     if 'Raw' in p.summary() and b'exe' in p.load and b'HTTP' in p.load:
#         client_ip = traffic[i][sc.IP].src
#         server_ip = traffic[i][sc.IP].dst
#         http_exe_start = i
#         break
# # finds the beginning of the exe 
# for i in range(http_exe_start, len(traffic)):
#     if traffic[i][sc.IP].src == server_ip and traffic[i][sc.IP].dst == client_ip:
#         if 'Raw' in traffic[i].summary() and b'\xfd' in traffic[i].load:
#             exe_start = i
#             break
# with open('test1.exe', 'wb') as exe:
#     for i in range(exe_start, len(traffic)):
#         if traffic[i][sc.IP].src == server_ip and traffic[i][sc.IP].dst == client_ip:
#             exe.write(traffic[i].load)
#             if 'FPA' in traffic[i].summary(): #end of the file/executable
#                 break

#passively listen to traffic until you notice a packet that looks like the 
#beginning of an exe download
#switch over to downloading the file

def find_exe_download_request():
    client_ip = ""
    server_ip = ""
    while (client_ip == "" and server_ip == ""):
        p=sc.sniff(count=1)
        if 'Raw' in p[0].summary() and b'exe' in p[0].load and b'HTTP' in p[0].load:
            client_ip = p[0][sc.IP].src
            server_ip = p[0][sc.IP].dst
    return (client_ip, server_ip)

def record_exe_download(client_ip, server_ip):
    start_recording = False
    with open('test1.exe', 'wb') as exe:
        while not start_recording:
            p=sc.sniff(count=1)
            if p[0][sc.IP].src == server_ip and p[0][sc.IP].dst == client_ip:
                if 'Raw' in p[0].summary() and b'\xfd' in p[0].load:
                    exe.write(p[0].load)
                    start_recording = True
        while start_recording:
            p=sc.sniff(count=1)
            if p[0][sc.IP].src == server_ip and p[0][sc.IP].dst == client_ip:
                exe.write(p[0].load)
                if 'FPA' in p[0].summary(): #end of the file/executable
                    start_recording = False

def main():
    client,server = find_exe_download_request()
    record_exe_download(client, server)

if __name__ == "__main__":
    main()
