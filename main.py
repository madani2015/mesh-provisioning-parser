from parser3 import *
from detector import ReflectionRandomDetector
if __name__ == "__main__":
    pkts = pyshark.FileCapture("nordic_provisioning.pcapng", display_filter="provisioning")
    pkts = pyshark.FileCapture("provisioning.cap", display_filter="provisioning")
    
    parsed = []
    
    detector = ReflectionRandomDetector()
     
    
    
    check_m = []
    check_s = []
    rand_dev = []
    rand_prov = []
    confirm_dev = []
    confirm_prov = []
    for pkt in pkts:
        pdu_type = pkt['PROVISIONING'].pdu_type # extract pdu_type
        if 'NORDIC_BLE' in pkt:
            direction = pkt['NORDIC_BLE'].direction
        #print(direction)
        
        if pdu_type == '0':
            parsed.append(MeshInvite(pkt))
            
        elif pdu_type == '1':
            parsed.append(MeshProvCaps(pkt))
            # __import__("ipdb").set_trace() - this is for debugging
            rand_prov = MeshRandom(pkt).random
            rand_dev = MeshRandom(pkt).random
            
            
            rand_prov_instance = MeshRandom(pkt)
            confirm_prov_instace= MeshConfirm(pkt)
            
            
            rand_dev_instance = MeshRandom(pkt)
            confirm_dev_instace= MeshConfirm(pkt)
            detector.rand_prov = rand_prov_instance
            detector.rand_dev = rand_dev_instance
            detector.conf_prov= confirm_prov_instace
            detector.confirm_dev= confirm_dev_instace
           
            
        elif pdu_type == '2':
            parsed.append(MeshStart(pkt))
        
        elif pdu_type == '3':
            parsed.append(MeshKeys(pkt))
        
        elif pdu_type == '5':
            mesh_confirm = MeshConfirm(pkt) #it is added
            parsed.append(mesh_confirm)
            #if detector.check_commitments(direction, confirm_dev[-1]):
            if confirm_dev:
                detector.check_commitments(direction, confirm_dev[-1])
            if detector.det:
                print(f"Reflection attack detected at packet number {pkt.number}!")
                break  # Break out of the loop when an attack is detected
            else: 
                     print(f"No reflection attack detected at packet number {pkt.number}.")

            
                
            # Check for relay attack during Commitments phase
            
            
            
        elif pdu_type == '6':
            parsed.append(MeshRandom(pkt))
            #if detector.check_nonce(direction, pkt['PROVISIONING'].random):
            if rand_dev:
                detector.check_nonce(direction, rand_dev[-1])
            if detector.det:
                print(f"Reflection attack detected at packet number {pkt.number}!")
                break  # Break out of the loop when an attack is detected
            else: 
                print(f"No reflection attack detected at packet number {pkt.number}.")

            
        
                
            
            
            
        elif pdu_type == '7':
            parsed.append(MeshDataPDU(pkt))
            
        elif pdu_type == '8':
            parsed.append(MeshComplete(pkt))
	
    else:
        print("No reflection attack detected. The network is safe.")
    




