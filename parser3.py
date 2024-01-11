import nest_asyncio
nest_asyncio.apply()
import pyshark


class MeshBase(object):
    """Base Class"""

    def __init__(self, packet: pyshark.packet.packet.Packet):
        if packet is not None:
            self.number = int(packet.number)
            self.pdu_type = int(packet['PROVISIONING'].pdu_type)
            self.padding = packet['PROVISIONING'].pdu_padding
        else:
            # Set default values if packet is None
            self.number = 0
            self.pdu_type = 0
            self.padding = 0
       
        
        
        print(f" BaseClass: number {self.number}")
        print(f" BaseClass: pdu type {self.pdu_type}")
        print(f" BasClass : pdu padding {self.padding}")
        
        
    def __repr__(self):
    	return str(vars(self))
        
class MeshInvite(MeshBase):
    """Class for Provisioning Invite, PDU=0"""

    def __init__(self, packet: pyshark.packet.packet.Packet): 
        super().__init__(packet) 
        self.attention= packet['provisioning'].attention_duration
        print(f"MeshInvite: attention    {self.attention}")
        
        


class MeshProvCaps(MeshBase):
    """Class to parse Provisioning capabilities PDU=1"""

    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        prov_layer = packet['PROVISIONING']
        self.algo= prov_layer.algorithms
        self.oos= prov_layer.output_oob_size
        self.ooa= prov_layer.output_oob_action
        self.ios= prov_layer.input_oob_size
        self.ioa= prov_layer.input_oob_action
        print(f"MeshProvCaps : algorithm {self.algo}")
        print(f"MeshProvCaps : output oob data size {self.oos}")
        print(f"MeshProvCaps : output oob data action {self.ooa}")
        print(f"MeshProvCaps : input oob data size {self.ios}")
        print(f"MeshProvCaps : input oob action {self.ioa}")
        
        
        
        

class MeshStart(MeshBase):
    """Class to indicate the start of provisioning PDU=2"""
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        prov_layer = packet['PROVISIONING']
        self.auth = prov_layer.authentication_method
        self.authalgo = prov_layer.algorithm
        self.publickey= prov_layer.public_key
        
        print(f"MeshStart : authentication method {self.auth}")
        print(f"MeshStart : algorithm {self.authalgo}")
        print(f"MeshStart : public key  {self.publickey}")
        
        
        
        
        
        
class MeshKeys(MeshBase):
    "Class to get public keys PDU=3"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        prov_layer = packet['PROVISIONING']
        self.public_key_x= prov_layer.public_key_x
        self.public_key_y = prov_layer.public_key_y
        print(f"Meshkeys : public key x {self.public_key_x}")
        print(f"Meshkeys : public key y {self.public_key_y}")
        
        
         
class MeshConfirm(MeshBase):
    "Class to get confirmation PDU=5"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        prov_layer = packet['PROVISIONING']
        if hasattr(prov_layer, 'confirmation') and prov_layer.confirmation is not None:
            self.confirm= prov_layer.confirmation
            print(f"MeshConfirm : confirmation {self.confirm}")
        
        else:
            print("MeshConfirm : confirmation field is None or does not exist")
        
        
    
class MeshRandom(MeshBase):
    "Class to get random PDU=6"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        prov_layer = packet['PROVISIONING']
        self.random = None
        if hasattr(prov_layer, 'random') and prov_layer.random is not None:
            self.random = prov_layer.random
            print(f"MeshRandom : random {self.random}")
        else:
            print("MeshRandom : random field is None or does not exist")
       
        print(f"MeshRandom : random {self.random}")
        
       
    
class MeshDataPDU(MeshBase):
    "Class to get Provisioning Data PDU PDU=7"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        prov_layer = packet['PROVISIONING']
       
        self.encrypt= prov_layer.encrypted_provisioning_data
        self.decrypt= prov_layer.decrypted_provisioning_data_mic
       
        print(f"MeshDataPDU : encrypted provisioning data {self.encrypt}")
        print(f"MeshDataPDU : decrypted provisioning data mic {self.decrypt}")
        
        
    
class MeshComplete(MeshBase):
    "Class to get Provisioning Complete PDU=8"
    
    def __init__(self, packet: pyshark.packet.packet.Packet):
        super().__init__(packet)
        
        print(f"MeshComplete ")
        
        
    
    
if __name__ == "__main__":
    pkts = pyshark.FileCapture("nordic_provisioning.pcapng", display_filter="provisioning")
    pkts = pyshark.FileCapture("provisioning.cap", display_filter="provisioning")
    
    
    parsed = []
    check_m = []
    check_s = []
    rand_dev= []
    rand_prov = []
    
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
                    #print ("REFLECTION ATTACK! BREAK THE PROGRAM")
                    break
                else:
                    #print ("\033[1mCheck for reflection attack: Commitements phase\033[0m\n\033[1mNo reflection attack detected:\033[0m commitment from master", check_m, "doesnt equal to commitment from slave", check_s)
                    check_m.clear()
                    check_s.clear()
                    #print("\n")
            
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
                    #print ("REFLECTION ATTACK! BREAK THE PROGRAM")
                    break
                else:
                    #print ("\033[1mCheck for reflection attack: Nonce phase\033[0m\n\033[1mNo reflection attack detected:\033[0m nonce from master", check_m, "doesnt equal nonce from slave", check_s)
                    check_m.clear()
                    check_s.clear()
                    #print("\n")
            
            
        elif pdu_type == '7':
            parsed.append(MeshDataPDU(pkt))
            
        elif pdu_type == '8':
            parsed.append(MeshComplete(pkt))
	
    #__import__('pdb').set_trace()
    




