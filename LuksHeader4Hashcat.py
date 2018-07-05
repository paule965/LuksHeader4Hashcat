#!/usr/bin/python

#Source: https://github.com/paule965/LuksHeader4Hashcat.py
#rr-20180706

import binascii, sys, codecs, datetime, os

#dump the first 4096 sectors
def main(args):
	f = open(sys.argv[1], 'rb')
	HeaderData = f.read(2097664) 
	FilePath = os.path.abspath(sys.argv[1])
	f.close()

#is it a valid LUKS?
	if not str(binascii.hexlify(HeaderData[0:6]).decode("ascii")) == "4c554b53babe":
		print("Wrong LUKS-Magic! Check/ Change it - exit.")
		return

#is it version1?
	if not str(binascii.hexlify(HeaderData[6:8]).decode("ascii")) == "0001":
		print("Wrong LUKS-Version! The script support this time only Version1.")
		return

#parse LUKSDATA
	LUKSMagic=HeaderData[0:6]
	LUKSVersion=HeaderData[6:8]
	LUKSCipherName=HeaderData[8:40]
	LUKSCipherMode=HeaderData[40:72]
	LUKSCipherSpec=HeaderData[72:104]
	LUKSPayloadOffset=HeaderData[104:108]
	LUKSKeyBytes=HeaderData[108:112]
	LUKSMasterkey=HeaderData[112:132]
	LUKSMasterkeySalt=HeaderData[132:164]
	LUKSMasterkeyIterations=HeaderData[164:168]
	LUKSUUID=HeaderData[168:208]

#look for Payloadoffset...
	PayloadOffset =  (int(binascii.hexlify(LUKSPayloadOffset).decode("ascii"),16))
	if PayloadOffset <= 4096:
		PayloadData = HeaderData[592:2097664] #Keymaterial + 1 Sector Payload
	
#parse LUKSDATAKeyslots
	KeySlotsOffset=0
	LUKSKey=[]
	LUKSKeyValues={}
	for Keyslots in range(8):
		LUKSKeyValues[Keyslots] = (
			#State - 0
			binascii.hexlify(HeaderData[208+KeySlotsOffset:212+KeySlotsOffset]).decode("ascii"),
			#Iterations - 1
			HeaderData[212+KeySlotsOffset:216+KeySlotsOffset], 
			#Salt - 2
			HeaderData[216+KeySlotsOffset:248+KeySlotsOffset], 
			#sector for keymaterial - 3
			HeaderData[248+KeySlotsOffset:252+KeySlotsOffset],
			#AF-stripes - 4
			HeaderData[252+KeySlotsOffset:256+KeySlotsOffset],
			
												)
		KeySlotsOffset=KeySlotsOffset + 48

#output of parsed Informations
	print("##############################################################################################################\n")
	print("Basic-Data")
	print("----------")
	print("Date/ Time (YYYY-MM-DD HH:MM:SS):  " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%d")))
	print("FileName(arg1):                    " + sys.argv[1])
	print("ScriptName(arg0):                  " + sys.argv[0])
	print("Filepath:                          " + FilePath)
	print("############################################################\n")
	print("Luks-Basic-Data")
	print("---------------")
	print("LUKS-Magic:                        " + str(binascii.hexlify(LUKSMagic).decode("ascii")))
	print("LUKS-Version:                      " + str(binascii.hexlify(LUKSVersion).decode("ascii")))
	print("LUKS-CipherName:                   " + codecs.decode(LUKSCipherName, 'utf-8')) 
	print("LUKS-CipherMode:                   " + codecs.decode(LUKSCipherMode, 'utf-8'))
	print("LUKS-CipherSpec:                   " + codecs.decode(LUKSCipherSpec, 'utf-8'))
	print("LUKS-PayloadOffset (Hex):          " + str(binascii.hexlify(LUKSPayloadOffset).decode("ascii")))
	print("LUKS-KeyBytes:                     " + str(binascii.hexlify(LUKSKeyBytes).decode("ascii")))
	print("LUKS-Masterkey:                    " + str(binascii.hexlify(LUKSMasterkey).decode("ascii")))
	print("LUKS-MasterkeySalt:                " + str(binascii.hexlify(LUKSMasterkeySalt).decode("ascii")))
	print("LUKS-MasterkeyIterations:          " + str(int(binascii.hexlify(LUKSMasterkeyIterations),16)))
	print("LUKS-UUID:                         " + codecs.decode(LUKSUUID, 'utf-8'))
	print("##############################################################################################################\n")


#if PayLoadoffset> 4096 read/copy 1. payloadsector
	if PayloadOffset > 4096:
		print("PayloadOffset is > 4096, use PayloadSector " + str(PayloadOffset) + ".\n")
		print("###########################################################\n")
		f = open(sys.argv[1], 'rb')
		PayloadOffsetData = f.read(512 * (PayloadOffset + 1))
		PayloadData = HeaderData[592:2097152] + PayloadOffsetData[102400000:102400512]
		BitList = ['00','00','10','00']
		PayLoadBinData = binascii.a2b_hex(''.join (BitList))
		HeaderDataTMP = HeaderData[:104] + PayLoadBinData + HeaderData[108:208]
		f.close()

	print("Luks-Keyslot-Data\n")
	print("Status		SlotNumber	Iterations	MeyMaterialSector	AF-Stripes")
	print("----------------------------------------------------------------------------------")
#find active Keys
	PossibleKeyslots = []
	for key in LUKSKeyValues.keys():
		if LUKSKeyValues[key][0][4:8] != "dead":
#somtimes i see different values in Field0 :S
			if str(LUKSKeyValues[key][0]) == "00ac71f3": # is active keyslot
				print("ACTIVE-Slot:	" + str(key) + "		" + str(int(binascii.hexlify(LUKSKeyValues[key][1]).decode("ascii"),16)) + "		" + str("%#5.4X"% (int(binascii.hexlify(LUKSKeyValues[key][3]).decode("ascii"),16)))  + "			" + str(int(binascii.hexlify(LUKSKeyValues[key][4]).decode("ascii"),16)))
				PossibleKeyslots.append(key)
			else:
				print("ACTIVE-Slot:	" + str(key) + "		" + str(int(binascii.hexlify(LUKSKeyValues[key][1]).decode("ascii"),16))
							 + " Iterations - !!! ATTENTION, ABNORMAL Field0.Value: " + str(LUKSKeyValues[key][0]) + " !!!")
				PossibleKeyslots.append(key)
		else:
#find dead Keys - sometimes (valid?) data inside...
			if int((binascii.hexlify(LUKSKeyValues[key][1])).decode("ascii"),16) != 0:
				print("DEAD-Slot:	" + str(key) + "		" + str(int(binascii.hexlify(LUKSKeyValues[key][1]).decode("ascii"),16))  + "		" + str("%#5.4X"% (int(binascii.hexlify(LUKSKeyValues[key][3]).decode("ascii"),16))) + "			" + str(int(binascii.hexlify(LUKSKeyValues[key][4]).decode("ascii"),16)))
				print ("!!! ATTENTION on KeySlot " + str(key)  + ", ABNORMAL Field0.Value: " + str(LUKSKeyValues[key][0]) + ", check KeySlots- and KeyMaterialentrys !!!")
				PossibleKeyslots.append(key)
#if u like empty entries...
			else:
				print("EMPTY-Slot:	" + str(key) + "		-" + "		-" + "			-")
	print("##################################################################################\n")

#rebuild the LuksHeader
	intKeySlot = ""
	while (not intKeySlot) and (not intKeySlot in PossibleKeyslots):
		intKeySlot = raw_input("Which KeySlot should be used? Possible is " + str(PossibleKeyslots) + ": ") 
		if not intKeySlot in str(PossibleKeyslots):
			print('Your Input is not a possible KeySlot, exiting Script')
			return

	intKeySlot = int(intKeySlot)

#rewrite LuksHeader
	print("\nYour Choice is KeySlot" +  str(intKeySlot) + ".\n")
	FilePathTMP = FilePath + "_KeySlot" + str(intKeySlot) + ".bin"
	FileInt = 1
	while os.path.isfile(FilePathTMP):
		FilePathTMP = FilePath + "_KeySlot" + str(intKeySlot) + "(" + str(FileInt) + ")" + ".bin"
		FileInt += 1
	FilePath = FilePathTMP
	print("Write to File:         " + FilePath)
	f = open(FilePath, 'wb')
	f.write(HeaderData[:208]) 
	
#write KeySlots	
	ByteListDEADKeyFirst=['00','00','DE','AD','00','00','00','00','00','00','00','00','00',
					 '00','00','00','00','00','00','00','00','00','00','00','00','00',
					 '00','00','00','00','00','00','00','00','00','00','00','00','00',
					 '00','00','00']
	ByteListDEADKeyThird=['08','00','00','0F','A0']
	for i in 0,1,2,3,4,5,6,7:
		if intKeySlot == i:
			ByteList=['00','AC','71','F3'] 											#set activ
			f.write(binascii.a2b_hex(''.join (ByteList)))
			f.write(LUKSKeyValues[intKeySlot][1]) 									#iterations
			f.write(LUKSKeyValues[intKeySlot][2])									#salt
			f.write(LUKSKeyValues[intKeySlot][3])									#sector KeyMaterial
			f.write(LUKSKeyValues[intKeySlot][4])									#AF
		else:
			f.write(binascii.a2b_hex(''.join (ByteListDEADKeyFirst)))
			f.write(binascii.a2b_hex("0" + str(i)))
			f.write(binascii.a2b_hex(''.join (ByteListDEADKeyThird)))
	f.write(PayloadData)
	f.close()

	return
	
if __name__ == '__main__':
	main(sys.argv)
