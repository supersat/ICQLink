/********* ICQ Link ************
 * Copyright 1999 Karl Koscher *
 *******************************/

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "resource.h"

#define ICQResolv 0x10
#define ICQ		0x11
#define EMailResolv 0x20
#define EMail 0x21
#define WM_RESOLVEICQ WM_USER + 22
#define WM_RESOLVEEMAIL WM_USER + 23
#define WM_ICQ	WM_USER + 40
#define WM_EMAIL WM_USER + 69


HWND hWndMain;


typedef struct SOCKETSTRUCT {
	SOCKET fd;
	unsigned int type;
	void *data;
	struct SOCKETSTRUCT *next;
} socketstruct;

typedef struct {
	unsigned short version;
	unsigned long reserved;
	unsigned long uin;
	unsigned long session;
	unsigned short command;
	unsigned short seqnum1;
	unsigned short seqnum2;
	unsigned long checksum;
	char buf[512]; //take advantage of ICQ's lazyness and static buffers
} ICQsend;

typedef struct {
	unsigned short version;
	unsigned char reserved;
	unsigned long session;
	unsigned short command;
	unsigned short seqnum1;
	unsigned short seqnum2;
	unsigned long myuin;
	unsigned long checksum;
	char buf[512]; //take advantage of ICQ again! This could be fun!
} ICQrecv;

typedef struct ICQpacketstruct {
	ICQsend data;
	unsigned int len;
	unsigned int lastsendtime;
	unsigned short seqnum1;
	unsigned short seqnum2;
	int retries;
	struct ICQpacketstruct *next;
	struct ICQpacketstruct *prev; // there shouldn't be many of these... not a memory issue
} ICQpacket;

typedef struct {
	struct sockaddr_in host;
	unsigned int uin;
	unsigned int status;
	ICQpacket *firstICQpacket;
	unsigned int session;
	unsigned int seqnum1;
	unsigned int seqnum2;
	unsigned int servseqnum1;
	unsigned int servseqnum2;
	unsigned int tcpport;
	unsigned int lastkeepalive;
	struct hostent *hostent;
} ICQconnectiondata;

typedef struct {
	//struct sockaddr_in host;
	struct hostent *hostent;
	int status;
	char *from;
	char *to;
	char *msg;
} EMAILdata;

typedef struct aUserMapping {
	unsigned int uin;
	char *nick;
	char *ph;
	struct aUserMapping *next;
} UserMapping;


typedef struct aUnknownUserMsg {
	unsigned int uin;
	char *msg;
	struct aUnknownUserMsg *next;
} UnknownUserMsg;

UserMapping *firstuser = NULL;
UnknownUserMsg *firstmsg = NULL;


void LoginToICQ(ICQconnectiondata *icd);
void SendICQAck(socketstruct *orig, unsigned int seqnum1, unsigned int seqnum2);
void ICQKeepAlive(ICQconnectiondata *icd);
int HandleICQCommand(ICQconnectiondata *icd, ICQrecv *packet);
int SendEmail(char *server, char *from, char *to, char *msg);

socketstruct *firstsock = NULL;

void ReadMappings()
{
	UserMapping *user = NULL;
	char buf[1024], *c, *n;
	FILE *f;
	f = fopen("uins.dat", "rt");
	while (fgets(buf, 1024, f)) {
		if (user)
			user = user->next = malloc(sizeof(UserMapping));
		else
			firstuser = user = malloc(sizeof(UserMapping));
		user->uin = atoi(buf);
		for (c = buf; *c && (*c != '\n') && (*c != '\t'); c++);
		if (*c == '\t') {
			c++;
			for (n = c; *n && (*n != '\n') && (*n != '\t'); n++);
			if (*n == '\t')
				*n++ = 0;
			else
				*n = 0;
			user->nick = strdup(c);
			if (*n)
				user->ph = strdup(n);
			else
				user->ph = NULL;
		} else 
			user->ph = user->nick = NULL;
	}
	user->next = NULL;
	fclose(f);
}




//////// Net stuff //////

int ConnectToICQ(unsigned int uin)
{
	socketstruct *IRCsock;


	if (firstsock) { // Add socket to linked list
		for (IRCsock = firstsock; IRCsock->next; IRCsock = IRCsock->next);
		IRCsock = IRCsock->next = malloc(sizeof(socketstruct));
	} else
		IRCsock = firstsock = malloc(sizeof(socketstruct));
	IRCsock->next = NULL;

	IRCsock->type = ICQResolv;
 	IRCsock->data = malloc(sizeof(ICQconnectiondata)); // max structure size
	((ICQconnectiondata *)IRCsock->data)->hostent = malloc(1024);
	
	((ICQconnectiondata *)IRCsock->data)->uin = uin;
	((ICQconnectiondata *)IRCsock->data)->firstICQpacket = NULL;
	((ICQconnectiondata *)IRCsock->data)->tcpport = 0;
	((ICQconnectiondata *)IRCsock->data)->seqnum1 = rand();
	((ICQconnectiondata *)IRCsock->data)->seqnum2 = 0;
	((ICQconnectiondata *)IRCsock->data)->session = (rand() << 16) + rand();
	((ICQconnectiondata *)IRCsock->data)->status = 4;
	IRCsock->fd = (unsigned int)WSAAsyncGetHostByName(hWndMain, WM_RESOLVEICQ, "icq.mirabilis.com", (char *)((ICQconnectiondata *)IRCsock->data)->hostent, 1024);
	
	return 0;
}

int ConnectToICQAsync(WPARAM wParam, LPARAM lParam)
{
	socketstruct *sock, *lastsock = NULL;
	int i;
	struct sockaddr_in remote;
	for (sock = firstsock; sock && ((sock->type != ICQResolv) || (sock->fd != wParam)); sock = sock->next)
		lastsock = sock;
	if (!sock)
		return (-1);
	memset(&remote, 0, sizeof(remote));
	remote.sin_family=AF_INET;

		remote.sin_port = htons(4000);
		memcpy(&remote.sin_addr, ((ICQconnectiondata *)sock->data)->hostent->h_addr_list[0], ((ICQconnectiondata *)sock->data)->hostent->h_length);

	if ((sock->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) { // Create Socket
		free(sock);
		if (lastsock) 
			lastsock->next = NULL;
		else
			firstsock = NULL;
		free(sock->data);
		free(sock);
		return(-2);
	}
	sock->type = ICQ;
	//BindLocalRandomPort(sock->fd);
	i = WSAAsyncSelect(sock->fd, hWndMain, WM_ICQ, FD_READ);
	memcpy(&((ICQconnectiondata *)sock->data)->host, &remote, sizeof(struct sockaddr_in));
	LoginToICQ((ICQconnectiondata *)sock->data);
	SetTimer(hWndMain, 40, 5000, NULL);
}

void CheckICQPackets()
{
	socketstruct *icq;
	ICQpacket *packet;
	unsigned int curtime = time(NULL);
	for (icq = firstsock; icq; icq = icq->next) {
		if (icq->type == ICQ) {
			for (packet = ((ICQconnectiondata *)icq->data)->firstICQpacket; packet; packet = packet->next) {
				if (curtime - packet->lastsendtime > 10000) { 
				
					sendto(icq->fd, (char *)&packet->data, packet->len, 0, (struct sockaddr *)&((ICQconnectiondata *)icq->data)->host, sizeof(struct sockaddr_in));
					packet->retries++;
					packet->lastsendtime = time(NULL);
				}
			}
			if (curtime > ((ICQconnectiondata *)icq->data)->lastkeepalive + 120) {
				((ICQconnectiondata *)icq->data)->lastkeepalive = time(NULL);
				ICQKeepAlive((ICQconnectiondata *)icq->data);
			}
		}
	}
}

HRESULT HandleICQMsg(WPARAM wParam, LPARAM lParam)
{
	ICQrecv packet;
	ICQpacket *qued;
	socketstruct *sock;
	int i, len;
	char *offset;

	for (sock = firstsock; sock && (sock->fd != wParam); sock = sock->next);
	if (!sock)
		return -1;
	recvfrom(sock->fd, (char *)&packet, sizeof(packet), 0, NULL, 0);
	if (packet.session != ((ICQconnectiondata *)sock->data)->session) { // someone is sp00fing!
		return -1;
	}
	if (packet.command == 10) { // ACK
		for (qued = ((ICQconnectiondata *)sock->data)->firstICQpacket; qued && ((qued->seqnum1 != packet.seqnum1) || (qued->seqnum2 != packet.seqnum2)); qued = qued->next);
		if (qued) {
			if (qued->prev)
				qued->prev->next = qued->next;
			else
				((ICQconnectiondata *)sock->data)->firstICQpacket = qued->next;
			free(qued);
		}
		return 0;
	}
	SendICQAck(sock, packet.seqnum1, packet.seqnum2);
	// check for dupes here
	((ICQconnectiondata *)sock->data)->servseqnum1 = packet.seqnum1;
	((ICQconnectiondata *)sock->data)->servseqnum2 = packet.seqnum2;
	if (packet.command == 530) { // multiple packets. joy.
		offset = packet.buf + 1;
		for (i = 0; i < *packet.buf; i++) {
			len = *(unsigned short *)offset;
			offset += 2;
			HandleICQCommand((ICQconnectiondata *)sock->data, (ICQrecv *)offset);
			offset += len;
		}
		return 0;
	}
	return HandleICQCommand((ICQconnectiondata *)sock->data, &packet);
}

///// More fun stuff //////

static const BYTE magictable[] = {
 0x59, 0x60, 0x37, 0x6B, 0x65, 0x62, 0x46, 0x48,
 0x53, 0x61, 0x4C, 0x59, 0x60, 0x57, 0x5B, 0x3D,
 0x5E, 0x34, 0x6D, 0x36, 0x50, 0x3F, 0x6F, 0x67,
 0x53, 0x61, 0x4C, 0x59, 0x40, 0x47, 0x63, 0x39,
 0x50, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x43, 0x69,
 0x48, 0x33, 0x31, 0x64, 0x35, 0x5A, 0x4A, 0x42,
 0x56, 0x40, 0x67, 0x53, 0x41, 0x07, 0x6C, 0x49,
 0x58, 0x3B, 0x4D, 0x46, 0x68, 0x43, 0x69, 0x48,
 0x33, 0x31, 0x44, 0x65, 0x62, 0x46, 0x48, 0x53,
 0x41, 0x07, 0x6C, 0x69, 0x48, 0x33, 0x51, 0x54,
 0x5D, 0x4E, 0x6C, 0x49, 0x38, 0x4B, 0x55, 0x4A,
 0x62, 0x46, 0x48, 0x33, 0x51, 0x34, 0x6D, 0x36,
 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x63,
 0x59, 0x40, 0x67, 0x33, 0x31, 0x64, 0x35, 0x5A,
 0x6A, 0x52, 0x6E, 0x3C, 0x51, 0x34, 0x6D, 0x36,
 0x50, 0x5F, 0x5F, 0x3F, 0x4F, 0x37, 0x4B, 0x35,
 0x5A, 0x4A, 0x62, 0x66, 0x58, 0x3B, 0x4D, 0x66,
 0x58, 0x5B, 0x5D, 0x4E, 0x6C, 0x49, 0x58, 0x3B,
 0x4D, 0x66, 0x58, 0x3B, 0x4D, 0x46, 0x48, 0x53,
 0x61, 0x4C, 0x59, 0x40, 0x67, 0x33, 0x31, 0x64,
 0x55, 0x6A, 0x32, 0x3E, 0x44, 0x45, 0x52, 0x6E,
 0x3C, 0x31, 0x64, 0x55, 0x6A, 0x52, 0x4E, 0x6C,
 0x69, 0x48, 0x53, 0x61, 0x4C, 0x39, 0x30, 0x6F,
 0x47, 0x63, 0x59, 0x60, 0x57, 0x5B, 0x3D, 0x3E,
 0x64, 0x35, 0x3A, 0x3A, 0x5A, 0x6A, 0x52, 0x4E,
 0x6C, 0x69, 0x48, 0x53, 0x61, 0x6C, 0x49, 0x58,
 0x3B, 0x4D, 0x46, 0x68, 0x63, 0x39, 0x50, 0x5F,
 0x5F, 0x3F, 0x6F, 0x67, 0x53, 0x41, 0x25, 0x41,
 0x3C, 0x51, 0x54, 0x3D, 0x5E, 0x54, 0x5D, 0x4E,
 0x4C, 0x39, 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F,
 0x47, 0x43, 0x69, 0x48, 0x33, 0x51, 0x54, 0x5D,
 0x6E, 0x3C, 0x31, 0x64, 0x35, 0x5A, 0x00, 0x00,
};


int logindata[] = { 2, 0, 0xd50008, 0x50, 3, 0 }; // last number is random... keep in mind in case mirabilis blocks us

ICQconnectiondata *FindFirstICQ()
{
	socketstruct *sock;
	for (sock = firstsock; sock && sock->type != ICQ; sock = sock->next);
	if (sock)
		return (ICQconnectiondata *)sock->data;
	return NULL;
}

unsigned int calcICQchecksum(unsigned char *packet, int len)
{
	unsigned int number1, number2, r1, r2;
	
	number1 = packet[8];
  	number1 <<= 8;
  	number1 |= packet[4];
	number1 <<= 8;
	number1 |= packet[2];
	number1 <<= 8;
	number1 |= packet[6];

	//r1 = 0x18 + (rand() % (len - 0x18));     --- THIS WILL CAUSE UNRELIABILITY
	//r2 = rand() % 0xFF;
	r1 = 0x18;  // CHANGE LATER
	r2 = rand() % 0xFF;
	
	number2 = r1;
	number2 <<= 8;
	number2 += packet[r1];
	number2 <<= 8;
	number2 += r2;   
	number2 <<= 8;
	number2 += magictable[r2];
	number2 ^= 0xff00ff;
	
	return (number1 ^ number2);
}

void encryptICQpacket(unsigned char *packet, unsigned int len)
{
	unsigned int i, checksum, enccode, finalchecksum;
	unsigned long checkscram[5], *mangle;

	checksum = calcICQchecksum(packet, len);
	//memcpy(packet + 0x14, &checksum, 4);
	enccode = len * 0x68656c6c + checksum;
	
	for(i = 0xa; i < len; i += 4) {
		mangle = (unsigned long *)(packet + i);
		*mangle ^= enccode + magictable[i & 0xFF]; // seems fishy
	}

	checkscram[0] = checksum & 0x0000001F;
	checkscram[1] = checksum & 0x03E003E0;
	checkscram[2] = checksum & 0xF8000400;
	checkscram[3] = checksum & 0x0000F800;
	checkscram[4] = checksum & 0x041F0000;
    
	checkscram[0] <<= 0x0C;
	checkscram[1] <<= 0x01;
	checkscram[2] >>= 0x0A;
	checkscram[3] <<= 0x10;
	checkscram[4] >>= 0x0F;
    
	finalchecksum = checkscram[0] + checkscram[1] + checkscram[2] + checkscram[3] + checkscram[4];
	memcpy(packet + 0x14, &finalchecksum, 4); // check the packet + 0x14 if it doesn't work
}


void SendICQPacket(ICQconnectiondata *icd, ICQsend *rawpacket, int len) // send the pointer instead of PUSHing all that shit
{
	ICQpacket *packet, *prev;
	if (icd->firstICQpacket) {
		for (packet = icd->firstICQpacket; packet->next; packet = packet->next);
		prev = packet;
		packet = packet->next = malloc(sizeof(ICQpacket));
	} else {
		prev = NULL;
		icd->firstICQpacket = packet = malloc(sizeof(ICQpacket));
	}
	packet->seqnum1 = rawpacket->seqnum1 = ++icd->seqnum1; //avoid duping this in EVERY function
	packet->seqnum2 = rawpacket->seqnum2 = ++icd->seqnum2;
	rawpacket->session = icd->session;
	rawpacket->version = 5;
	rawpacket->reserved = 0;
	rawpacket->checksum = 0;
	rawpacket->uin = icd->uin;
	*(unsigned int *)((char *)rawpacket + len) = 0; // encryption padding


	encryptICQpacket((char *)rawpacket, len);

	memcpy(&packet->data, rawpacket, len);
	packet->len = len;
	packet->lastsendtime = 0;
	packet->retries = -1; // when the inital packet is sent, this will be 0
	packet->next = NULL;
	packet->prev = prev;
	CheckICQPackets(); // ship the bitch out immediately
}

void LoginToICQ(ICQconnectiondata *icd)
{

	int i;
	char *password, *offset;
	ICQsend packet;

	icd->session = rand(); // let's grab a session ID here
	packet.command = 1000;
	i = time(NULL);
	memcpy(packet.buf, &i, 4);
	i = icd->tcpport;
	memcpy(packet.buf + 4, &i, 4);
	//GetICQRegString(icd->uin, "password", password, 256);  //encryption is pointless... and if the password doesn't exist, we'll get a bad login reply
	password = "REMOVED";
	i = strlen(password) + 1;
	memcpy(packet.buf + 8, &i, 2);
	memcpy(packet.buf + 10, password, i);
	offset = packet.buf + 10 + i;
	i = 0xd5;
	memcpy(offset, &i, 4);
	i = 0x0100007f; // localhost IP... fix later if mirabilis bitches
	memcpy(offset + 4, &i, 4);
	i = 0x06; // No TCP for the time being
	memcpy(offset + 8, &i, 1);
	memcpy(offset + 9, &icd->status, 4);
	memcpy(offset + 13, logindata, 24);
	icd->lastkeepalive = time(NULL);
	SendICQPacket(icd, &packet, offset + 61 - packet.buf);
}

void LogoffToICQ()
{
	socketstruct *sock;
	ICQsend packet;
	for (sock = firstsock; sock && (sock->type != ICQ); sock = sock->next);
	if (!sock)
		return;
	packet.command = 1080;
	memcpy(packet.buf, "\020\000B_USER_DISCONNECTED\000\005", 25); // \000 is added automagically
	SendICQPacket((ICQconnectiondata *)sock->data, &packet, 48);
}

void SendICQAck(socketstruct *orig, unsigned int seqnum1, unsigned int seqnum2)
{
	ICQsend packet;
	packet.command = 10;
	packet.seqnum1 = seqnum1;
	packet.seqnum2 = seqnum2;
	packet.version = 5;
	packet.reserved = 0;
	packet.session = ((ICQconnectiondata *)orig->data)->session;
	packet.uin = ((ICQconnectiondata *)orig->data)->uin;
	encryptICQpacket((char *)&packet, 28);
	sendto(orig->fd, (char *)&packet, 28, 0, (struct sockaddr *)&((ICQconnectiondata *)orig->data)->host, sizeof(struct sockaddr_in));
}


void ICQKeepAlive(ICQconnectiondata *icd)
{
	ICQsend packet;
	packet.command = 1070;
	SendICQPacket(icd, &packet, 28);
}

void SendICQMessageToServer(ICQconnectiondata *icd, unsigned int uin, char *msg)
{
	int i;
	ICQsend packet;
	packet.command = 270;
	memcpy(packet.buf, &uin, 4);
	i = 1;
	memcpy(packet.buf + 4, &i, 2);
	i = strlen(msg) + 1;
	memcpy(packet.buf + 6, &i, 2);
	memcpy(packet.buf + 8, msg, i);
	SendICQPacket(icd, &packet, 32 + i);
}


int ICQRecvMsg(ICQconnectiondata *icd, ICQrecv *packet)
{
	UserMapping *user;
	char from[256], buf[1024], t;
	int i, len;
	SendICQMessageToServer(icd, *(unsigned long *)packet->buf, "I'm not here, but your message has been sent to my pager.");
	for (user = firstuser; user && user->uin != *(unsigned long *)packet->buf; user = user->next);
	if (user) {
		strcpy(from, user->nick);
		if (user->ph)
			sprintf(buf, "%s\n%s", user->ph, packet->buf + 8);
		else
			strcpy(buf, packet->buf + 8);
	} else {
		sprintf(from, "%u", *(unsigned long *)packet->buf);
		strcpy(buf, packet->buf + 8);
	}
	len = strlen(buf);
	for (i = 0; i < len; i += 120) {
		t = *(buf + i + 120);
		*(buf + i + 120) = 0;
		SendEmail("mail.teleport.com", from, "cell@teencity.org", buf + i);
		*(buf + i + 120) = t;
	}
	SendEmail("mail.teleport.com", from, "mrsaturn@ureach.com", packet->buf + 8);
	return 1;
}

int HandleICQCommand(ICQconnectiondata *icd, ICQrecv *packet)
{
	switch (packet->command) {
	case 40:
	case 240:
		LoginToICQ(icd);
		return 1;
	//case 90:
//		return SendContactList(icd);
	//case 110:
//		return ICQUserOnline(icd, packet);
	case 260:
		return ICQRecvMsg(icd, packet);
	default:
		return 0;
	}
}
////// windows shit ////


int SendEmail(char *server, char *from, char *to, char *msg)
{
	socketstruct *IRCsock;


	if (firstsock) { // Add socket to linked list
		for (IRCsock = firstsock; IRCsock->next; IRCsock = IRCsock->next);
		IRCsock = IRCsock->next = malloc(sizeof(socketstruct));
	} else
		IRCsock = firstsock = malloc(sizeof(socketstruct));
	IRCsock->next = NULL;

	IRCsock->type = EMailResolv;
 	IRCsock->data = malloc(sizeof(ICQconnectiondata)); // max structure size
	((EMAILdata *)IRCsock->data)->hostent = malloc(1024);
	((EMAILdata *)IRCsock->data)->from = strdup(from);
	((EMAILdata *)IRCsock->data)->to = strdup(to);
	((EMAILdata *)IRCsock->data)->msg = strdup(msg);
	((EMAILdata *)IRCsock->data)->status = 0;
	
	IRCsock->fd = (unsigned int)WSAAsyncGetHostByName(hWndMain, WM_RESOLVEEMAIL, "mail.teleport.com", (char *)((EMAILdata *)IRCsock->data)->hostent, 1024);
	
	return 0;
}


int ConnectToEMailAsync(WPARAM wParam, LPARAM lParam)
{
	socketstruct *sock, *lastsock = NULL;
	struct sockaddr_in remote;
	for (sock = firstsock; sock && ((sock->type != EMailResolv) || (sock->fd != wParam)); sock = sock->next)
		lastsock = sock;
	if (!sock)
		return (-1);
	memset(&remote, 0, sizeof(remote));
	remote.sin_family=AF_INET;
	remote.sin_port=htons(25);

		memcpy(&remote.sin_addr, ((EMAILdata *)sock->data)->hostent->h_addr_list[0], ((EMAILdata *)sock->data)->hostent->h_length);

	if ((sock->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) { // Create Socket
		free(sock);
		if (lastsock) 
			lastsock->next = NULL;
		else
			firstsock = NULL;
		free(((EMAILdata *)sock->data)->from);
		free(((EMAILdata *)sock->data)->to);
		free(((EMAILdata *)sock->data)->msg);
		free(sock->data);
		free(sock);
		return(-2);
	}
	sock->type = EMail;

	WSAAsyncSelect(sock->fd, hWndMain, WM_EMAIL, FD_READ);
	connect(sock->fd, (struct sockaddr *)&remote, 16);
	if (WSAGetLastError() != WSAEWOULDBLOCK) {
		closesocket(sock->fd);
		free(((EMAILdata *)sock->data)->from);
		free(((EMAILdata *)sock->data)->to);
		free(((EMAILdata *)sock->data)->msg);
		free(sock->data);
		free(sock);
		if (lastsock) 
			lastsock->next = NULL;
		else
			firstsock = NULL;

		return(-4);
	}
	return 0;
	
}
void ProcessMailAsync(WPARAM wParam, LPARAM lParam)
{
	socketstruct *sock, *lastsock = NULL;
	char buf[2048], *c;
	for (sock = firstsock; sock && ((sock->type != EMail) || (sock->fd != wParam)); sock = sock->next)
		lastsock = sock;
	if (!sock)
		return;
	recv(sock->fd, buf, 2048, 0);
	c = buf;
	while (1) {

		if (!strncmp(c, "220 ", 4)) {
			sprintf(buf, "HELO nexchat.com\n");
			send(sock->fd, buf, strlen(buf), 0);
			return;
		}
		if (!strncmp(c, "250 ", 4)) {
			switch (((EMAILdata *)sock->data)->status) {
			case 0:
				sprintf(buf, "MAIL FROM: %s <mrsaturn@teleport.com>\n", ((EMAILdata *)sock->data)->from);
				break;
			case 1:
				sprintf(buf, "RCPT TO: Pager <%s>\n", ((EMAILdata *)sock->data)->to);
				break;
			case 2:
				sprintf(buf, "DATA\n");
				break;
			case 3:
				sprintf(buf, "QUIT\n");
			}
			((EMAILdata *)sock->data)->status++;
			send(sock->fd, buf, strlen(buf), 0);
			return;
		}
	
		if (!strncmp(c, "354 ", 4)) {
			sprintf(buf, "From: %s\r\n\r\n%s\r\n\r\n.\r\n", ((EMAILdata *)sock->data)->from, ((EMAILdata *)sock->data)->msg);
			send(sock->fd, buf, strlen(buf), 0);
			return;
		}
		if (!strncmp(c, "221 ", 4)) {
			closesocket(sock->fd);
			free(((EMAILdata *)sock->data)->from);
			free(((EMAILdata *)sock->data)->to);
			free(((EMAILdata *)sock->data)->msg);
			free(sock->data);
			free(sock);
			if (lastsock) 			
				lastsock->next = NULL;
			else
				firstsock = NULL;
		}	
		for (; *c && (*c != '\n'); c++);
		if (!*c)
			break;
		else 
			c++;
	}
}
	
		
	
BOOL WINAPI MainProc(HWND hwnd, UINT msg, UINT wParam, LONG lParam)
{
	
	switch (msg) {
	case WM_INITDIALOG:
		srand(time(NULL));
		hWndMain = hwnd;
		ConnectToICQ(548324);

		return 1;
	case WM_TIMER:
		CheckICQPackets();
		return 1;
	case WM_COMMAND:
		LogoffToICQ();
		EndDialog(hwnd, 0);
		return 1;
	case WM_RESOLVEICQ:
		ConnectToICQAsync(wParam, lParam);
		return 1;
	case WM_ICQ:
		HandleICQMsg(wParam, lParam);
		return 1;
	case WM_RESOLVEEMAIL:
		ConnectToEMailAsync(wParam, lParam);
		return 1;
	case WM_EMAIL:
		ProcessMailAsync(wParam, lParam);
		return 1;

	default:
		return 0;
	}
}



int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInstance,
				   LPSTR lpszCmdLine, int nCmdShow)
{
	WSADATA wsa;
	WSAStartup(0x101, &wsa);
	ReadMappings();
	return DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG1), NULL, MainProc);
	WSACleanup();
}
