#! /usr/bin/python3

import socket
import os
import sys
from struct import *

PROTOCOL_TCP = 6

def PacketExtractor(packet):
	stripPacket = packet[0:20]

	ipHeaderTuple = unpack('!BBHHHBBH4s4s' , stripPacket)

	verLen = ipHeaderTuple[0]
	TOS = ipHeaderTuple[1]
	packetLength = ipHeaderTuple[2]
	packetID = ipHeaderTuple[3]
	flagFrag = ipHeaderTuple[4]
	RES = (flagFrag >> 15) & 0x01
	DF = (flagFrag >> 14) & 0x01
	MF = (flagFrag >> 13) & 0x01
	timeToLive = ipHeaderTuple[5]
	protocol = ipHeaderTuple[6]
	checkSum = ipHeaderTuple[7]
	sourceIP = ipHeaderTuple[8]
	destIP = ipHeaderTuple[9]

	version = verLen >> 4
	length = verLen & 0x0F
	ipHdrLength = length * 4

	sourceAddress = socket.inet_ntoa(sourceIP);
	destinationAddress = socket.inet_ntoa(destIP);

	if protocol == PROTOCOL_TCP:
		stripTCPHeader = packet[ipHdrLength:ipHdrLength+20]

		tcpHeaderBuffer = unpack('!HHLLBBHHH' , stripTCPHeader)

		sourcePort = tcpHeaderBuffer[0]
		destinationPort = tcpHeaderBuffer[1]
		sequenceNumber = tcpHeaderBuffer[2]
		acknowledgement = tcpHeaderBuffer[3]
		dataOffsetAndReserve = tcpHeaderBuffer[4]
		tcpHeaderLength = (dataOffsetAndReserve >> 4) * 4
		flags = tcpHeaderBuffer[5]
		FIN = flags & 0x01
		SYN = (flags >> 1) & 0x01
		RST = (flags >> 2) & 0x01
		PSH = (flags >> 3) & 0x01
		ACK = (flags >> 4) & 0x01
		URG = (flags >> 5) & 0x01
		ECE = (flags >> 6) & 0x01
		CWR = (flags >> 7) & 0x01
		windowSize = tcpHeaderBuffer[6]
		tcpChecksum = tcpHeaderBuffer[7]
		urgentPointer = tcpHeaderBuffer[8]

		if sourcePort < 1024:
			serverIP = sourceAddress
			clientIP = destinationAddress
			serverPort = sourcePort
		elif destinationPort < 1024:
			serverIP = destinationAddress
			clientIP = sourceAddress
			serverPort = destinationPort
		else:
			serverIP = "Filter"
			clientIP = "Filter"
			serverPort = "Filter"

		return([serverIP, clientIP, serverPort], [SYN, serverIP, TOS, timeToLive, DF, windowSize])

	else:
		return(["Filter", "Filter", "Filter"], [NULL, NULL, NULL, NULL, NULL, NULL])

if __name__=='__main__':

	ret = os.system("ifconfig eth0 promisc")

	if ret == 0:
		print("eth0 configured in promiscuous mode")
		try:
			mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
			print("Raw socket open")
		except:
			print("Raw Socket Open Failed")
			sys.exit()

		ipObeservations = []
		osObservations = []

		maxObservations = 500

		portValue = 443

		try:
			while maxObservations > 0:
				recvBuffer, addr = mySocket.recvfrom(255)
				content, fingerPrint = PacketExtractor(recvBuffer)

				if content[0] != "Filter":
					if content[2] == portValue:
						ipObeservations.append(content)
						maxObservations = maxObservations - 1
						if fingerPrint[0] == 1:
							osObservations.append([fingerPrint[1], \
								fingerPrint[2], \
								fingerPrint[3], \
								fingerPrint[4], \
								fingerPrint[5]])
						else:
							continue
					else:
						continue
				except:
					print("Socket failure")
					exit()
ret = os.system("ifconfig eth0 -promisc")

mySocket.close()

uniqueSrc = set(map(tuple, osObservations))
finalList = list(uniqueSrc)
finalList.sort()

uniqueFingerPrints = set(map(tuple, osObservations))
finalFingerPrintList = list(uniqueFingerPrints)
finalFingerPrintList.sort()


print("Unique Packets")
for packet in finalList:
	print packet
print("Unique Fingerprints")
for osFinger in finalFingerPrintList:
	print(osFinger)
else:
	print("Prmiscuous Mode Not Set")


