import scapy.all as sc

traffic = sc.sniff(offline='C:\\Users\\C\\Documents\\GitHub\\PythonBackdoor\\assets\\pcap\\specific.pcapng')
client_ip = ""
server_ip = ""
http_exe_start = 0
exe_start = 0

#finds the beginning of the http exe request
for i in range(0, len(traffic)):
    p = traffic[i]
    if 'Raw' in p.summary() and b'exe' in p.load and b'HTTP' in p.load:
        client_ip = traffic[i][sc.IP].src
        server_ip = traffic[i][sc.IP].dst
        http_exe_start = i
        break

for i in range(http_exe_start, len(traffic)):
    if traffic[i][sc.IP].src == server_ip and traffic[i][sc.IP].dst == client_ip:
        if 'Raw' in traffic[i].summary() and b'\xfd' in traffic[i].load:
            exe_start = i
            break
print(exe_start)
with open('test1.exe', 'wb') as exe:
    for i in range(exe_start, len(traffic)):
        if traffic[i][sc.IP].src == server_ip and traffic[i][sc.IP].dst == client_ip:
            exe.write(traffic[i].load)
            if 'FPA' in traffic[i].summary(): #end of the file/executable
                break
        #beginning of a exe should be MZ byte or b'\xfd'
        #after the first HTTP get request for an EXE
        #wait for the first Push, ACK from the server
        # start writing data until
        # we get the next HTTP OK from the Server indicating the file is over




