import nest_asyncio
nest_asyncio.apply()
import pyshark

#set of classes where each class is decoding a specific packet
class MeshBase(object):
    """Base Class"""

def __init__(self, packet: pyshark.packet.packet.Packet):
        self.number = int(packet.number)                             # pb with the packet.nbr
        self.pdu_type = int(pkt['PROVISIONING'].pdu_type) 
        
        self.public_key_type = packet['PROVISIONING'].public_key_type   #values that we need from the packet
        self.number_of_elements = packet['PROVISIONING'].number_of_elements
        self.algorithms = packet['PROVISIONING'].algorithms
        self.authentication_method = packet['PROVISIONING'].authentication_method
        self.public_key_x = packet['PROVISIONING'].public_key_x
        self.public_key_y = packet['PROVISIONING'].public_key_y
        self.confirmation = packet['PROVISIONING'].confirmation
        self.random = packet['PROVISIONING'].random
        self.encrypted_provisioning_data = packet['PROVISIONING'].encrypted_provisioning_data
        self.decrypted_provisioning_data_mic = packet['PROVISIONING'].decrypted_provisioning_data_mic
        
def __repr__(self):
    	   return str(vars(self))
        
class MeshInvite(MeshBase):
    """Class for Provisioning Invite, PDU=0"""

    def __init__(self, packet: pyshark.packet.packet.Packet): 
        #super().__init__(self) 
        #in order to call the base class you should use this line of the code
        
    
        print("\033[1mFeature exchange start\033[0m packet number is", packet.number)
        print("\n")


class MeshProvCaps(MeshBase):
    """Class to parse Provisioning capabilities PDU=1"""

    def __init__(self, packet: pyshark.packet.packet.Packet):
        #super().__init__(self)
        if (packet['PROVISIONING'].algorithms == '0x0001'):
            provisioning_type = "P-256 Elliptic Curve: Available."
        else:
            provisioning_type = "Unknown. Or check field <algorithms> in the same packet."
        
        print("Here devices exchange their IO capabilities and algorithms supported.\nPacket of type Provisioning Capabilities PDU with number", packet.number,
              "with encryption algorithms:", provisioning_type,
              "with public key type", packet['PROVISIONING'].public_key_type, 
              "contains", packet['PROVISIONING'].number_of_elements, "elements, and using algorithm", 
              packet['PROVISIONING'].algorithms)
        print("\n")
        

class MeshStart(MeshBase):
    """Class to indicate the start of provisioning PDU=2"""
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        if (packet['PROVISIONING'].authentication_method == '0'):
            auth_method = "Provisioning is not authenticated"
        elif (packet['PROVISIONING'].authentication_method == '1'):
            auth_method = "Provisioning is authenticated."
        else:
            auth_method = "Provisioning is not authenticated."
        print(auth_method, ", with authentication type", packet['PROVISIONING'].authentication_method)
        print("\n\033[1mThis is the end of feature exchange\033[0m")
        print("\n\033[1mProvisioning start\033[0m")
        print("\n")
        
class MeshKeys(MeshBase):
    "Class to get public keys PDU=3"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        print("\033[1mThis is Key Exchange step.\033[0m Packet Provisioning Public Key PDU with number", packet.number, "has public key X:",
              packet['PROVISIONING'].public_key_x, "and public key Y:", packet['PROVISIONING'].public_key_y )
        print("\n")
    
class MeshConfirm(MeshBase):
    "Class to get confirmation PDU=5"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        print("\033[1mThis is Authentication step: Commitments phase.\033[0m Packet Provisioning Confirmation PDU with number", packet.number, "received confirmation", packet['PROVISIONING'].confirmation)
        print("\n")
    
class MeshRandom(MeshBase):
    "Class to get random PDU=6"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        print("\033[1mThis is Authentication step: Nonce phase.\033[0m Packet Provisioning Random PDU with number", packet.number, "has random", packet['PROVISIONING'].random)
        print("\n")
    
class MeshDataPDU(MeshBase):
    "Class to get Provisioning Data PDU PDU=7"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        print("\033[1mThis is provisioning end.\033[0mPacket Provisioning Random PDU with number", packet.number, "has following network key", packet['PROVISIONING'].encrypted_provisioning_data, 
             "and following decrypted data", packet['PROVISIONING'].decrypted_provisioning_data_mic)
        print("\n")
    
class MeshComplete(MeshBase):
    "Class to get Provisioning Complete PDU=8"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        print("\033[1mPacket Provisioning Complete\033[0m PDU has finished with packet number", packet.number)
        print("\n")

    
    
if __name__ == "__main__":
    pkts = pyshark.FileCapture("nordic_provisioning.pcapng", display_filter="provisioning")
    
    parsed = []
    check_m = []
    check_s = []
    for pkt in pkts:
        pdu_type = pkt['PROVISIONING'].pdu_type # extract pdu_type
        direction = pkt['NORDIC_BLE'].direction
        #print(direction)
        
        if pdu_type == '0':
            parsed.append(MeshInvite(pkt))
            
        elif pdu_type == '1':
            parsed.append(MeshProvCaps(pkt))
            # __import__("ipdb").set_trace() - this is for debugging
            
        elif pdu_type == '2':
            parsed.append(MeshStart(pkt))
        
        elif pdu_type == '3':
            parsed.append(MeshKeys(pkt))
        
        elif pdu_type == '5':
            parsed.append(MeshConfirm(pkt))
            if (direction == '1'):
                check_m.append((pkt['PROVISIONING'].confirmation))
                #print("this is confirmation from master ", check_m)
            if (direction == '0'):
                check_s.append((pkt['PROVISIONING'].confirmation))
                #print("this is confirmation from slave ", check_s)
            if (len(check_m)>0 and len(check_s)>0):
                if (check_m == check_s):
                    print ("REFLECTION ATTACK! BREAK THE PROGRAM")
                    break
                else:
                    print ("\033[1mCheck for reflection attack: Commitements phase\033[0m\n\033[1mNo reflection attack detected:\033[0m commitment from master", check_m, "doesnt equal to commitment from slave", check_s)
                    check_m.clear()
                    check_s.clear()
                    print("\n")
            
        elif pdu_type == '6':
            parsed.append(MeshRandom(pkt))
            if (direction == '1'):
                check_m.append((pkt['PROVISIONING'].random))
                #print("this is nonce from master ", check_m)
            if (direction == '0'):
                check_s.append((pkt['PROVISIONING'].random))
                #print("this is nonce from slave ", check_s)
            if (len(check_m)>0 and len(check_s)>0):
                if (check_m == check_s):
                    print ("REFLECTION ATTACK! BREAK THE PROGRAM")
                    break
                else:
                    print ("\033[1mCheck for reflection attack: Nonce phase\033[0m\n\033[1mNo reflection attack detected:\033[0m nonce from master", check_m, "doesnt equal nonce from slave", check_s)
                    check_m.clear()
                    check_s.clear()
                    print("\n")
            
            
        elif pdu_type == '7':
            parsed.append(MeshDataPDU(pkt))
            
        elif pdu_type == '8':
            parsed.append(MeshComplete(pkt))
	
    #__import__('pdb').set_trace()
    




