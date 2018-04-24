#!/usr/bin/python

import binascii, sys, codecs, datetime, os

#dump the first 4096 sectors
def main(args):
	f = open(sys.argv[1], 'rb')
	HeaderData = f.read(2097664) 
	FilePath = os.path.abspath(sys.argv[1])	
	f.close()
	
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
		PayloadData = HeaderData[592:2097664]
	
##############################################
##############################################
#if PayLoadoffset> 4096 rewrite the file!
	if PayloadOffset > 4096:
		f = open(sys.argv[1], 'rb')
		PayloadOffsetData = f.read(512 * (PayloadOffset + 1))
		PayloadData = HeaderData[592:2097152] + PayloadOffsetData[102400000:102400512]
		BitList = ['00','00','10','00']
		PayLoadBinData = binascii.a2b_hex(''.join (BitList))
		HeaderDataTMP = HeaderData[:104] + PayLoadBinData + HeaderData[108:208]
		f.close()
##############################################
##############################################
#parse LUKSDATAKeyslots
	KeySlotsOffset=0
	LUKSKey=[]
	LUKSKeyValues={}
	for Keyslots in range(8):
		LUKSKeyValues[Keyslots] = (
														#State
															binascii.hexlify(HeaderData[208+KeySlotsOffset:212+KeySlotsOffset]).decode("ascii"),
														#Iterations
															HeaderData[212+KeySlotsOffset:216+KeySlotsOffset], 
														#Salt
															HeaderData[216+KeySlotsOffset:248+KeySlotsOffset], 
														#KeyNumber do i need it???
															binascii.hexlify(HeaderData[248+KeySlotsOffset:256+KeySlotsOffset]).decode("ascii"),
															)	
		KeySlotsOffset=KeySlotsOffset + 48
#Krücke :S		
	HeaderData = HeaderDataTMP
	
	print("############################################################")
	print()
	print("Basic-Data")
	print("----------")
	print("Date/ Time (YYYY-MM-DD HH:MM:SS): " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%d")))
	print("FileName(arg1): " + sys.argv[1])
	print("ScriptName(arg0): " + sys.argv[0])
	print("Filepath: " + FilePath)
	print("############################################################")
	print()
	print("Luks-Basic-Data")
	print("---------------")
	print("LUKS-Magic:" + str(binascii.hexlify(LUKSMagic).decode("ascii")))
	print("LUKS-Version: " + str(binascii.hexlify(LUKSVersion).decode("ascii")))
	print("LUKS-CipherName: " + codecs.decode(LUKSCipherName, 'utf-8')) 
	print("LUKS-CipherMode: " + codecs.decode(LUKSCipherMode, 'utf-8'))
	print("LUKS-CipherSpec: " + codecs.decode(LUKSCipherSpec, 'utf-8'))
	print("LUKS-PayloadOffset (inhex): " + str(binascii.hexlify(LUKSPayloadOffset).decode("ascii")))
	print("LUKS-KeyBytes: " + str(binascii.hexlify(LUKSKeyBytes).decode("ascii")))
	print("LUKS-Masterkey: " + str(binascii.hexlify(LUKSMasterkey).decode("ascii")))
	print("LUKS-MasterkeySalt: " + str(binascii.hexlify(LUKSMasterkeySalt).decode("ascii")))
	print("LUKS-MasterkeyIterations: " + str(int(binascii.hexlify(LUKSMasterkeyIterations),16)))
	print("LUKS-UUID: " + codecs.decode(LUKSUUID, 'utf-8'))
	print("############################################################")
	print()
	print("Luks-Keyslots-Data")
	print("------------------")
	PossibleKeyslots = []
	for key in LUKSKeyValues.keys():
#find active Keys
		if LUKSKeyValues[key][0][4:8] != "dead":
#somtimes i see different values in Field0 :S
			if str(LUKSKeyValues[key][0]) == "00ac71f3":																						
				print("active-Slot: " + str(key) + " with " + str(int(binascii.hexlify(LUKSKeyValues[key][1]).decode("ascii"),16)) + " Iterations")
				PossibleKeyslots.append(key)
			else:
				print("active-Slot: " + str(key) + " with " + str(int(binascii.hexlify(LUKSKeyValues[key][1]).decode("ascii"),16))
							 + " Iterations - !!! ATTENTION, ABNORMAL Field0.Value: " + str(LUKSKeyValues[key][0]) + " !!!")
				PossibleKeyslots.append(key)
		else:
#find dead Keys		
			if int((binascii.hexlify(LUKSKeyValues[key][1])).decode("ascii"),16) != 0:
				print("  dead-Slot: " + str(key) + " with " + str(int(binascii.hexlify(LUKSKeyValues[key][1]).decode("ascii"),16))
							 + " Iterations - !!! ATTENTION, ABNORMAL Field0.Value: " + str(LUKSKeyValues[key][0]) + " !!!")
				PossibleKeyslots.append(key)
#if u like empty entries...
#			else:
#				print(" empty-Slot: " + str(key))
	print("############################################################")
	print()
	print()

#rebuild the LuksHeader
	intKeySlot = int(input("Which KeySlot should be extracted? possibilities: " + str(PossibleKeyslots) + ": "))
	print()
	print("Your Choice is KeySlot" +  str(intKeySlot) + ".")
	print()
	FilePath = FilePath + "_KeySlot" + str(intKeySlot) + ".bin"
	print("Write to FilePath: " + FilePath)
	f = open(FilePath, 'wb')
	f.write(HeaderData[:208]) 
#writing KeySlots	
	BitList=['00','AC','71','F3']
	f.write(binascii.a2b_hex(''.join (BitList)))
	f.write(LUKSKeyValues[intKeySlot][1])
	f.write(LUKSKeyValues[intKeySlot][2])
	BitList=['00','00','00','08', '00','00','0F','A0']
	f.write(binascii.a2b_hex(''.join (BitList)))
	BitList=['00','00','DE','AD','00','00','00','00','00','00','00','00','00',
					 '00','00','00','00','00','00','00','00','00','00','00','00','00',
					 '00','00','00','00','00','00','00','00','00','00','00','00','00',
					 '00','00','00','00','08','00','00','0F','A0']
	for i in 1,2,3,4,5,6,7:
			f.write(binascii.a2b_hex(''.join (BitList)))
	f.write(PayloadData)
	f.close()	

	return
	
if __name__ == '__main__':
	main(sys.argv)