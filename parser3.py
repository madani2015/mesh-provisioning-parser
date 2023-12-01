import nest_asyncio
nest_asyncio.apply()
import pyshark


class MeshBase(object):
    """Base Class"""

    def __init__(self, packet: pyshark.packet.packet.Packet):
        self.number = int(packet.number)                             # pb with the packet.nbr
        self.pdu_type = int(packet['PROVISIONING'].pdu_type) 
        #print(f" BaseClass: number {self.number}")
        #print(f" BaseClass: pdu type {self.pdu_type}")
        
    def __repr__(self):
    	return str(vars(self))
        
class MeshInvite(MeshBase):
    """Class for Provisioning Invite, PDU=0"""

    def __init__(self, packet: pyshark.packet.packet.Packet): 
        super().__init__(packet) 
        
        self.attention = packet['PROVISIONING'].attention_duration
        print(f"MeshInvite: attention {self.attention}")
        print("\n")


class MeshProvCaps(MeshBase):
    """Class to parse Provisioning capabilities PDU=1"""

    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        prov_layer = packet['PROVISIONING']
        self.algos = prov_layer.algorithms
        self.oos = prov_layer.output_oob_size
        print(f"MeshProvCaps: algos {self.algos}")
        print(f"MeshProvCaps: oos {self.oos}")
       
        

class MeshStart(MeshBase):
    """Class to indicate the start of provisioning PDU=2"""
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
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
        super().__init__(packet)
        print("\033[1mThis is Key Exchange step.\033[0m Packet Provisioning Public Key PDU with number", packet.number, "has public key X:",
              packet['PROVISIONING'].public_key_x, "and public key Y:", packet['PROVISIONING'].public_key_y )
        print("\n")
    
class MeshConfirm(MeshBase):
    "Class to get confirmation PDU=5"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        print("\033[1mThis is Authentication step: Commitments phase.\033[0m Packet Provisioning Confirmation PDU with number", packet.number, "received confirmation", packet['PROVISIONING'].confirmation)
        print("\n")
    
class MeshRandom(MeshBase):
    "Class to get random PDU=6"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        print("\033[1mThis is Authentication step: Nonce phase.\033[0m Packet Provisioning Random PDU with number", packet.number, "has random", packet['PROVISIONING'].random)
        print("\n")
    
class MeshDataPDU(MeshBase):
    "Class to get Provisioning Data PDU PDU=7"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        print("\033[1mThis is provisioning end.\033[0mPacket Provisioning Random PDU with number", packet.number, "has following network key", packet['PROVISIONING'].encrypted_provisioning_data, 
             "and following decrypted data", packet['PROVISIONING'].decrypted_provisioning_data_mic)
        print("\n")
    
class MeshComplete(MeshBase):
    "Class to get Provisioning Complete PDU=8"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
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
    




