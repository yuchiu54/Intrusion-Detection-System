from datetime import datetime

layer_table = {'Ethernet': [2, 0],    
     'IP': [3, 0],    
     'TCP': [4, 0],    
     'UDP': [4, 0],    
     'ICMP': [3, 0],    
     'Raw': [5, 0]}  


'''
{
    'address': 
        {
            'time': output of datime,
            'pkt_type': 
                {
                    'tcp': 0,
                    'udp': 0,
                    'icmp': 0
                }
    
        }
}
'''
ip_table = {}
