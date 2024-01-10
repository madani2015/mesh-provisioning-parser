from parser3 import MeshRandom,MeshConfirm


class ReflectionRandomDetector:
    
    
  
    def __init__(self, rand_prov: MeshRandom = None, rand_dev: MeshRandom = None, confirm_prov: MeshConfirm = None, confirm_dev: MeshConfirm = None):
       self.rand_prov = rand_prov
       self.rand_dev = rand_dev
       self.conf_prov = confirm_prov
       self.confirm_dev = confirm_dev
       self.check_commit_prov = []
       self.check_commit_dev = []
       self.det = False
       self.check_m = []
       self.check_s = []
    
    #if rand_prov.random == rand_dev.random:
            #self.det = True


    def check_commitments(self, direction, confirmation):
        if self.confirm_dev is not None and self.conf_prov is not None and self.conf_prov.confirmation == self.confirm_dev.confirmation:
            self.det = True
        else:
            self.det = False
        
        

        if len(self.check_m) > 0 and len(self.check_s) > 0:
            if self.check_m == self.check_s:
                self.det = True  # Reflection attack detected
            else:
                self.check_m.clear()
                self.check_s.clear()
                self.det = True  # No reflection attack detected

    def check_nonce(self, direction, random):
         if self.rand_prov is not None and self.rand_dev is not None and self.rand_prov.random == self.rand_dev.random:
            self.det = True
         else:
            self.det = False
         
        

         if len(self.check_m) > 0 and len(self.check_s) > 0:
            if self.check_m == self.check_s:
                self.det = True  # Reflection attack detected
            else:
                self.check_m.clear()
                self.check_s.clear()
                self.det = False  # No reflection attack detected

