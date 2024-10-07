#   Benjamin DELPY `gentilkiwi`
#   https://blog.gentilkiwi.com / 
#   benjamin@gentilkiwi.com
#   Licence : https://creativecommons.org/licenses/by/4.0/
#
#   High Level Analyzer for NXP PN532 NFC chip on SPI bus
#   SPI settings:
#    - Significant Bit:   LSB
#    - Bits per Transfer: 8
#    - Clock State:       CPOL = 0
#    - Clock Phase:       CPHA = 0
#    - Enable Line:       Active Low

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame
from enum import Enum

class PN532_DECODER_STATE(Enum):
    START = 0
    GET_OPERATION = 1
    STATUS_READING = 2
    DATA_READING = 3
    DATA_WRITING = 4
    RAW = 5

PN532_CMD = {
    0x00: 'Diagnose',
    0x02: 'GetFirmwareVersion',
    0x04: 'GetGeneralStatus',
    0x06: 'ReadRegister',
    0x08: 'WriteRegister',
    0x0c: 'ReadGPIO',
    0x0e: 'WriteGPIO',
    0x10: 'SetSerialBaudRate',
    0x12: 'SetParameters',
    0x14: 'SAMConfiguration',
    0x16: 'PowerDown',
    0x32: 'RFConfiguration',
    0x58: 'RFRegulationTest',
    0x56: 'InJumpForDEP',
    0x46: 'InJumpForPSL',
    0x4a: 'InListPassiveTarget',
    0x50: 'InATR',
    0x4e: 'InPSL',
    0x40: 'InDataExchange',
    0x42: 'InCommunicateThru',
    0x44: 'InDeselect',
    0x52: 'InRelease',
    0x54: 'InSelect',
    0x60: 'InAutoPoll',
    0x8c: 'TgInitAsTarget',
    0x92: 'TgSetGeneralBytes',
    0x86: 'TgGetData',
    0x8e: 'TgSetData',
    0x94: 'TgSetMetaData',
    0x88: 'TgGetInitiatorCommand',
    0x90: 'TgRespondToInitiator',
    0x8a: 'TgGetTargetStatus',
}

class Hla(HighLevelAnalyzer):
    
    def __init__(self):

        state = PN532_DECODER_STATE.START
        
    def decode(self, frame: AnalyzerFrame):

        if frame.type == 'enable':

            self.state = PN532_DECODER_STATE.GET_OPERATION
            self.bdata = bytearray()

        elif frame.type == 'result':
            
            if self.state == PN532_DECODER_STATE.GET_OPERATION:
                self.begin_frame = frame.start_time
                codeb = frame.data['mosi']
                code = codeb[0]
                
                if((code & 0x03) == 0x02):
                    self.state = PN532_DECODER_STATE.STATUS_READING
                elif((code & 0x03) == 0x03):
                    self.state = PN532_DECODER_STATE.DATA_READING
                elif((code & 0x03) == 0x01):
                    self.state = PN532_DECODER_STATE.DATA_WRITING
                else:
                    self.state = PN532_DECODER_STATE.RAW
                    self.bdata.extend(codeb)

            else:
                self.end_frame = frame.end_time
                codeb = frame.data['miso' if (self.state in [PN532_DECODER_STATE.STATUS_READING, PN532_DECODER_STATE.DATA_READING]) else 'mosi']
                self.bdata.extend(codeb)

                
        elif frame.type == 'disable':

            ret = None
            
            if(self.state in [PN532_DECODER_STATE.STATUS_READING, PN532_DECODER_STATE.DATA_READING, PN532_DECODER_STATE.DATA_WRITING, PN532_DECODER_STATE.RAW]):
                ret = self.myAnalyse()

            self.state = PN532_DECODER_STATE.START
            
            return ret

    def myAnalyse(self):
        
        cmd = None
        data = self.bdata
        
        l = len(self.bdata)
        
        if((self.state == PN532_DECODER_STATE.STATUS_READING) and (l == 1)):
            data = self.bdata
        
        elif((self.state == PN532_DECODER_STATE.DATA_READING) and (l >= 6) and (self.bdata[0:3] == b'\x00\x00\xff')):
            if(self.bdata[3:6] == b'\x00\xff\x00'):
                data = 'ACK'
            elif(self.bdata[3:6]== b'\xff\x00\x00'):
                data = 'NACK'
            elif(self.bdata[5] == 0xd5):
                cmd = PN532_CMD.get(self.bdata[6] - 1, '?')
                li = self.bdata[3] - 1;
                data = self.bdata[7:7+li-1]
            
        elif((self.state == PN532_DECODER_STATE.DATA_WRITING) and (l >= 9) and (self.bdata[3] > 1) and (self.bdata[5] == 0xd4)):
            cmd = PN532_CMD.get(self.bdata[6], '?')
            li = self.bdata[3] - 1;
            data = self.bdata[7:7+li-1]
        
        elif((self.state == PN532_DECODER_STATE.RAW) and (l == 6) and (self.bdata[0:3] == b'\x00\x00\xff')):
            if(self.bdata[3:6] == b'\x00\xff\x00'):
                data = 'ACK'
            elif(self.bdata[3:6]== b'\xff\x00\x00'):
                data = 'NACK'
        
        ret = {'data': data}
        if(cmd is not None):
            ret.update({'cmd': cmd})
            
        return AnalyzerFrame(self.state.name, self.begin_frame, self.end_frame, ret)
