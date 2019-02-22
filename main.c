#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include "dns.h"

#define IP      	0
#define DOMAIN  	1
#define DNS_PORT	53
#define SHRT_MAX	32766
#define IN 			1

/* Throw an error and exit program */
void error(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

/* Check if a short is in 0-255 range */
int isByte(short n) 
{
	return n >= 0 && n <= 255;
}

/* Chech the format of IP: XXX.XXX.XXX.XXX */
int checkIP(char *ip)
{
	char *p = ip;
	int index = 0;
	int lastByteIndex = 0;
	int numBytes = 0;

	// Verfy the pattern of an IP
	while (index <= strlen(ip))
	{
		if (p[index] == '.' || p[index] == '\0')
		{
			// Check the size of byte
			if (!lastByteIndex 
					&& (index - lastByteIndex > 3 
						|| index - lastByteIndex <= 0)) 
				return 0;
			else if (lastByteIndex
					&& (index - lastByteIndex - 1 > 3 
						|| index - lastByteIndex - 1 <= 0)) 
				return 0;

			lastByteIndex = index;
			numBytes++;

			// Check for too many bytes given
			if (numBytes > 4)
				return 0;

		}
		else if (p[index] < '0' || p[index] > '9')
			return 0;

		// Go to next character
		index++;
	}

	// Final verification of pattern
	if (numBytes != 4 || p[index] == '.')
		return 0;
	

	// Verify bytes of the IP
	unsigned short b1, b2, b3, b4;
	sscanf(ip, "%hu.%hu.%hu.%hu", &b1, &b2, &b3, &b4);
	if (!isByte(b1) || !isByte(b2) || !isByte(b3) || !isByte(b4))
		return 0;
	
	return 1;
}

/* Check the arguments */
int checkArgs(int argc, char **argv, TDNSQuery *dnsQuery)
{
	// Check the number of arguments
	if (argc != 3)
		error("Invalid number of arguments!");

	sscanf(argv[1], "%s", dnsQuery->serverInfo);

	// Check the type of the query
	if (checkIP(argv[1]))
		dnsQuery->type = IP;
	else
		dnsQuery->type = DOMAIN;

	// Type of the question for dns server
	if (!strcmp(argv[2], "A"))
		dnsQuery->query = A;
	else if (!strcmp(argv[2], "MX"))
		dnsQuery->query = MX;
	else if (!strcmp(argv[2], "NS"))
		dnsQuery->query = NS;
	else if (!strcmp(argv[2], "CNAME"))
		dnsQuery->query = CNAME;
	else if (!strcmp(argv[2], "SOA"))
		dnsQuery->query = SOA;
	else if (!strcmp(argv[2], "TXT"))
		dnsQuery->query = TXT;
	else if (!strcmp(argv[2], "PTR"))
		dnsQuery->query = PTR;

	return 1;
}

/**
 * Connect to dns server. This function returns sockfd for success and -1 for 
 * failure.
 */
int connectToServer(char *dnsServerIp)
{
	int sockfd;
	struct sockaddr_in serv_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		return -1;
	
	// Set timeout for receive and connect
	struct timeval timeVals = { 5, 0 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeVals, 
			   sizeof(struct timeval));

	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *) &timeVals, 
			sizeof(struct timeval));

	// Fullfil the serv_addr info
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(DNS_PORT);
	inet_aton(dnsServerIp, &serv_addr.sin_addr);
	
	// Connect
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		return -1;

	return sockfd;
}

/**
 * Convert domain name to size of labels followed by octets from labes. 
 */
int convDNtoLabels(char *domain, char **result) 
{
	unsigned char counter = 0;

	// Alloc memory 
	*result = (char *)malloc(strlen(domain) + 2);
	if (!*result)
		return 0;

	// Convert the domain
	char *p = *result + 1;
	while (1)
	{
		if (*domain == '.' || *domain == '\0') 
		{
			*(p - counter - 1) = counter;
			if (*domain == '\0')
				break;

			domain++;
			p++;
			counter = 0;
		}
		else 
		{
			if (*domain == '\0')
				break;

			*(p++) = *(domain++);
			counter++;
		}
	}

	// Put '\0' at the end of the string
	*p = '\0';

	// Succcess
	return 1;
}

/**
 * Convert address to ARPA notation (a.b.c.d -> d.c.b.a.in-addr.arpa)
 */
void convertToARPA(char *buf, char **res) 
{
	unsigned short b1, b2, b3, b4;

	*res = (char *)calloc(strlen(buf) + 15, sizeof(char));
	if (!*res)
		return;

	sscanf(buf, "%hu.%hu.%hu.%hu", &b1, &b2, &b3, &b4);
	sprintf(*res, "%hu.%hu.%hu.%hu.in-addr.arpa", b4, b3, b2, b1);
}

/**
 * Prin message from a buffer, in hexadecimal, in a file
 */
void printMsg(FILE *file, char *buffer) 
{
	unsigned short size, i;

	// Get the size of the payload
	memcpy(&size, buffer, sizeof(size));
	size = ntohs(size);

	// Print to file
	for (i = 0; i < size + 1; i++) 
		fprintf(file, "%02x ", buffer[i] & 0xff);
	fprintf(file, "%02x\n", buffer[i] & 0xff);
}

/**
 * Create payload to sent to DNS server, from query
 */
int createMsg(TDNSQuery *dnsQuery, char **payload, unsigned short *size)
{
	dns_header_t header;
	dns_question_t question;

	srand(time(NULL));
	
	// Set header
	memset(&header, 0, sizeof(dns_header_t));
	header.id = htons(rand() % SHRT_MAX);
	header.rd = 1;
	header.qdcount = htons(1);

	// Set question
 	if (dnsQuery->type == IP) 
	{
		char *aux;
		convertToARPA(dnsQuery->serverInfo, &aux);
		convDNtoLabels(aux, &question.qname);
		free(aux);
	}
	else 
		convDNtoLabels(dnsQuery->serverInfo, &question.qname);

	question.qtype = htons(dnsQuery->query);
	question.qclass = htons(IN);
	
	// Compute size and offset
	int nameLen = strlen(question.qname);
	*size = sizeof(dns_header_t) + sizeof(dns_question_t) - 8 + nameLen + 3;
	int offset = 2;

	// Allocate memory for payload
	*payload = (char*)malloc(*size * sizeof(char));
	if (!*payload)
		return 0;

	// Copy data to payload
	memcpy(*payload + offset, &header, sizeof(dns_header_t));
	offset += sizeof(dns_header_t);

	memcpy(*payload + offset, question.qname, nameLen + 1);
	offset += nameLen + 1;

	memcpy(*payload + offset, &question.qtype, 
		sizeof(dns_question_t) - sizeof(char*));

	// Put the size into payload (at the begining)
	unsigned short payloadSize = htons(*size - 2);
	memcpy(*payload, &payloadSize, sizeof(unsigned short));

	// Release memory and return 
	free(question.qname);
	return 1;
}

/**
 * Decompress a section from the buffer. It returns the next positions (returned
 * value and side effect).
 */
int decompressName(char *buf, unsigned short startIndex1,
				   char *result, unsigned short startIndex2, 
				   unsigned short *actualIndex, unsigned char maxLen)
{
	char hasPointer = 0;
	unsigned short orgStart = startIndex1;

	while (buf[startIndex1] != '\0') 
	{
		maxLen--;
		unsigned short offset;

		// Get 2 bytes and convert to Little-Endian
		memcpy(&offset, buf + startIndex1, sizeof(offset));
		offset = ntohs(offset);
		if (!hasPointer) {
			orgStart = startIndex1;
			
			// Check for maximum size
			if (maxLen <= 0) 
			{
				*actualIndex = orgStart + 1;
				result[startIndex2] = buf[startIndex1];
				return startIndex2;
			}
		}

		// If offset starts with 0x11 then we've got a pointer
		if ((offset & 0xC000) == 0xC000) 
		{
			*actualIndex = orgStart + 2;
			hasPointer = 1;
			startIndex1 = (offset & 0x3FFF) + 2;
			continue;
		}

		// Copy from buffer to result
		result[startIndex2] = buf[startIndex1];
		startIndex1++;
		startIndex2++;
	}

	// Put the '\0' to the end
	result[startIndex2] = buf[startIndex1];

	if (!hasPointer) 
		*actualIndex = startIndex1 + 1;
	
	// Return the next index to '\0'
	return startIndex2;
}

/**
 * Convert DNS numbered address to string (numbers in hexadecimal => '.')
 */
void toPrintableName(char *buf, char *res) 
{
	buf++;
	while (*buf != '\0')
	{
		if (*buf < 'a') 
		{
			*res = '.';
			if (*buf >= '0' && *buf <= '9')
				*res = *buf;
		}
		else 
			*res = *buf;

		res++;
		buf++;
	}

	*res = '\0';
}

/**
 * Print text in human readable
 */
void printText(char *buf, char *res) 
{
	buf++;
	while (*buf != '\0')
	{
		if (*buf < ' ' && *buf != '\n') 
			*res = '.';
		else 
			*res = *buf;

		res++;
		buf++;
	}

	*res = '\0';
}

/**
 * Convert number IPv4 to string IPv4
 */
void convBytesToIPv4(unsigned char *buf, char *res) 
{
	sprintf(res, "%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3]);
}

/**
 * Convert number IPv6 to string IPv6. It is possibile to have some bugs. 
 */
void convBytesToIPv6(unsigned char *buf, char *res) 
{
	sprintf(res, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
			buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], 
			buf[8], buf[9], buf[10], buf[11]);
}

/**
 * Print to file a rr message
 */
void printRR(FILE *logFile, dns_rr_t *rr) 
{
	unsigned short type = ntohs(rr->type);
	char name[BUFLEN], aux[BUFLEN], aux2[BUFLEN];
	unsigned short class = ntohs(rr->class);
	toPrintableName(rr->name, name);
	char addr[17];
	t_soa_dns soa;

	if (class != IN)
		return;

	// Print format for each type of query
	switch(type) 
	{
		case NS:
			toPrintableName(rr->rdata, aux);
			fprintf(logFile, "%s. IN NS %s.\n", name, aux);
			break;

		case A:
			convBytesToIPv4((unsigned char*)rr->rdata, addr);
			fprintf(logFile, "%s. IN A %s\n", name, addr);
			break;
		case AAAA:
			convBytesToIPv6((unsigned char*)rr->rdata, addr);
			fprintf(logFile, "%s. IN AAAA %s\n", name, addr);
			break;

		case MX:
			toPrintableName(rr->rdata + 2, aux);
			unsigned short pref;
			memcpy(&pref, rr->rdata, sizeof(pref));
			pref = ntohs(pref);
			fprintf(logFile, "%s. IN MX %d %s.\n", name, pref, aux);
			break;

		case CNAME:
			toPrintableName(rr->rdata, aux);
			fprintf(logFile, "%s. IN CNAME %s.\n", name,  aux);
			break;

		case SOA:
			memcpy(&soa, rr->rdata, sizeof(soa));
			toPrintableName(soa.adminMB, aux);
			toPrintableName(soa.primaryNS, aux2);
			fprintf(logFile, "%s. IN SOA %s. %s. %d %d %d %d %d\n", name, aux, 
				   aux2, soa.serial,soa.refresh, soa.retry, soa.expiration, 
				   soa.ttl);
			free(rr->rdata);
			break;
		
		case TXT:
			printText(rr->rdata, aux);
			fprintf(logFile, "%s. IN TXT \"%s\"\n", name, aux);
			break;

		case PTR:
			toPrintableName(rr->rdata, aux);
			fprintf(logFile, "%s. IN PTR %s.\n", name, aux);
			break;	

		default:
			break;
	}

}

/**
 * Get data from section
 */
void readSection(FILE *logFile, unsigned short ancount, char *buf, 
				 unsigned short *startSeq, char *result, 
				 unsigned short *crtSize)
{
	unsigned short i, n, nextIndex;
	unsigned int shortSize = sizeof(unsigned short);
	unsigned char rDataSize = 200;
	dns_rr_t rr;

	for (i = 0; i < ancount; i++)
	{
		// Read NAME
		n = decompressName(buf, *startSeq, result, *crtSize, &nextIndex,
						   rDataSize) + 1;
		rr.name = result + *crtSize;

		// Read TYPE, CLASS, TTL and RDLENGTH
		memcpy(result + n, buf + nextIndex, 5 * shortSize);
		memcpy(&rr.type, buf + nextIndex, 5 * shortSize);

		*crtSize = n + 5 * shortSize;
		*startSeq = nextIndex + 5 * shortSize;

		memcpy(&rDataSize, buf + *startSeq - 1, sizeof(char));
		unsigned short type = ntohs(rr.type);

		// Read RDATA
		if (type == NS || type == PTR)
		{
			n = decompressName(buf, *startSeq, result, *crtSize, &nextIndex,
							   rDataSize) + 1;
			rr.rdata = result + *crtSize;
			*crtSize = n;
			*startSeq = nextIndex;
		}
		else if (type == A)
		{
			memcpy(result + *crtSize, buf + *startSeq, rDataSize);
			rr.rdata = result + *crtSize;
			*crtSize += rDataSize;
			*startSeq += rDataSize;
		}
		else if (type == AAAA)
		{
			memcpy(result + *crtSize, buf + *startSeq, rDataSize);
			rr.rdata = result + *crtSize;
			*crtSize += rDataSize;
			*startSeq += rDataSize;
		}
		else if (type == MX)
		{
			// Copy Preference
			memcpy(result + *crtSize, buf + *startSeq, shortSize);
			*crtSize += shortSize;
			*startSeq += shortSize;

			n = decompressName(buf, *startSeq, result, *crtSize, &nextIndex,
							   rDataSize) + 1;
			rr.rdata = result + *crtSize - shortSize;

			*crtSize = n;
			*startSeq = nextIndex;
		}
		else if (type == CNAME)
		{
			n = decompressName(buf, *startSeq, result, *crtSize, &nextIndex,
							   rDataSize) + 1;
			rr.rdata = result + *crtSize;

			*crtSize = n;
			*startSeq = nextIndex;
		}
		else if (type == SOA)
		{
			t_soa_dns soa;
			memset(&soa, 0, sizeof(soa));

			// Primary NS
			n = decompressName(buf, *startSeq, result, *crtSize, &nextIndex,
							   rDataSize) + 1;
			soa.adminMB = result + *crtSize;

			*crtSize = n;
			*startSeq = nextIndex;

			// Admin MB
			n = decompressName(buf, *startSeq, result, *crtSize, &nextIndex,
							   rDataSize) + 1;
			soa.primaryNS = result + *crtSize;

			*crtSize = n;
			*startSeq = nextIndex;

			// 5 Unsigned 32-bit integers
			memcpy(result + *crtSize, buf + *startSeq, 5 * sizeof(int));
			memcpy(&soa.serial, buf + *startSeq, 5 * sizeof(int));
			soa.serial = htonl(soa.serial);
			soa.refresh = htonl(soa.refresh);
			soa.retry = htonl(soa.retry);
			soa.expiration = htonl(soa.expiration);
			soa.ttl = htonl(soa.ttl);

			*crtSize += 5 * sizeof(int);
			*startSeq += 5 * sizeof(int);

			rr.rdata = malloc(sizeof(soa));
			memcpy(rr.rdata, &soa, sizeof(soa));
		}
		else if (type == TXT)
		{
			n = decompressName(buf, *startSeq, result, *crtSize, &nextIndex,
							   rDataSize) + 1;
			rr.rdata = result + *crtSize;

			*crtSize = n;
			*startSeq = nextIndex;
		}

		printRR(logFile, &rr);
	}
}

/**
 * Get data from payload and print to file the result
 */
int getData(FILE *logFile, char *buf, char *dnsServerIp, char *query, 
			char *type)
{
	char result[BUFLEN];
	memset(result, 0, BUFLEN - 1);
	unsigned short sizeMsg, startSeq, crtSize = 0, n, i, nextIndex;
	unsigned int shortSize = sizeof(unsigned short);

	dns_header_t header;
	dns_question_t question;

	// Get the size of the message
	memcpy(&sizeMsg, buf, sizeof(sizeMsg));
	sizeMsg = ntohs(sizeMsg);

	// Get the header from message
	memcpy(&header, buf + 2, sizeof(header));

	if (header.qr != 1)
		return 0;

	startSeq = sizeof(header) + sizeof(unsigned short);
	crtSize = startSeq;
	memcpy(result, buf, startSeq);
	
	unsigned short qdcount = ntohs(header.qdcount);
	unsigned short ancount = ntohs(header.ancount);
	unsigned short nscount = ntohs(header.nscount);
	unsigned short arcount = ntohs(header.arcount);

	// Check for responses
	if (ancount == 0 && nscount == 0 && arcount == 0)
		return 0;

	// Decompress question section
	for (i = 0; i < qdcount; i++) 
	{	
		n = decompressName(buf, startSeq, result, crtSize, &nextIndex, 200) + 1;
		question.qname = result + crtSize;

		memcpy(result + n, buf + nextIndex, 2 * shortSize);
		memcpy(&question.qtype, buf + nextIndex, 2 * shortSize);

		crtSize = n + 2 * shortSize;
		startSeq = nextIndex + 2 * shortSize;
	}
	fprintf(logFile, "; %s - %s %s\n", dnsServerIp, query, type);

	if (ancount  != 0) 
	{
		// Decompress answer section
		fprintf(logFile, "\n;; ANSWER SECTION:\n");
		readSection(logFile, ancount, buf, &startSeq, result, &crtSize);
	}

	if (nscount  != 0) 
	{
		// Decompress authority section
		fprintf(logFile, "\n;; AUTHORITY SECTION:\n");
		readSection(logFile, nscount, buf, &startSeq, result, &crtSize);
	}

	if (arcount  != 0) 
	{
		// Decompress additional section
		fprintf(logFile, "\n;; ADDITIONAL SECTION:\n");
		readSection(logFile, arcount, buf, &startSeq, result, &crtSize);
	}

	fprintf(logFile, "\n\n");
	return 1;
}	

/**
 * Resolve a DNS
 */
int resolveDNS(FILE *logFile, char *dnsServerIp, TDNSQuery *dnsQuery, 
			   char *query, char *type, char *payload, unsigned short size) 
{
	char buf[BUFLEN];

	// Connect to server
	int sockfd = connectToServer(dnsServerIp);
	if (sockfd < 0)
		return 0;

	// Send payload
	if (send(sockfd, payload, size, 0) < 0)
		error("Error while writing to socket");

	// Receive payload
	memset(buf, 0, BUFLEN);
	if (recv(sockfd, buf, BUFLEN - 1, 0) < 0)
		return 0;

	// Extract data
	if (!getData(logFile, buf, dnsServerIp, query, type))
		return 0;

	// Close file and return
	close(sockfd);
	return 1;
}

/**
 * Try each DNS server until one responds to request
 */
int tryDnsServers(TDNSQuery *dnsQuery, char *query, char *type) 
{
	char buf[BUFLEN];
	char *payload;
	unsigned short size;

	FILE *file = fopen("dns_servers.conf", "rt");
	FILE *logFile = fopen("dns.log", "at");
	FILE *msgFile = fopen("message.log", "at");

	// Check for oppened files
	if (!file || !logFile || !msgFile) 
	{
		printf("Error while oppening files!\n");
		fclose(file);
		fclose(logFile);
		fclose(msgFile);
		return 0;
	}

	// Create payload
	if (!createMsg(dnsQuery, &payload, &size)) 
	{
		printf("Error while allocating memory!\n");
		fclose(file);
		fclose(logFile);
		fclose(msgFile);
		return 0;
	}

	// Log payload
	printMsg(msgFile, payload);

	// Try each DNS server
	while (fgets(buf, BUFLEN - 1, file))
	{	
		// Current line is empty or a comment
		if (buf[0] == '#' || buf[0] == '\n' || buf[0] == EOF)
			continue;
		
		// Remove '\n' from the end of the string
		buf[strlen(buf) - 1] = '\0';
		
		// Resolve DNS
		if (resolveDNS(logFile, buf, dnsQuery, query, type, payload, size)) {
			break;
		}
	}
	
	// Close files and exit
	fclose(file);
	fclose(logFile);
	fclose(msgFile);
	return 1;
}

/* Starting point of the program. */
int main(int argc, char **argv)
{
	TDNSQuery dnsQuery;

	checkArgs(argc, argv, &dnsQuery);
	tryDnsServers(&dnsQuery, argv[1], argv[2]);

	return 0;
}
