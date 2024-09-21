#!/usr/bin/python
# Importation des modules 

from mininet.net import Mininet #Importer la classe Mininet pour créer le reseau
from mininet.node import Controller # Classe controller pour les controleurs dans Mininet
from mininet.node import OVSKernelSwitch # Classe OVSKernelSwitch pour créer des commutateurs virtuels
from mininet.node import RemoteController # RemoteController pour connecter le réseau Mininet à un controleur externe
from mininet.cli import CLI # fournir une interface de ligne de commande pour tester le réseau
from mininet.log import setLogLevel #Pour la journalisation

def sdnsecTopo():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch) # creation d'une instance de Mininet indiquant que le réseau utilise un remote controller et des commutateurs OVS

    # Création du contrôleur RYU
    c0 = net.addController('Controller', controller=RemoteController, ip='127.0.0.1', port=6633)  # ajout du controleur RYU qui sera execute sur localhost au port 6633 

    # Ajout des hôtes et des commutateurs
    h1 = net.addHost('h1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02')
    s0 = net.addSwitch('s0', dpid='0000000000000001')
    s1 = net.addSwitch('s1', dpid='0000000000000002')
    s2 = net.addSwitch('s2', dpid='0000000000000003')
    s12 = net.addSwitch('s12', dpid='000000000000004')
    
    
    # Création des liens
    net.addLink(h1, s0)
    net.addLink(s0, s1)
    net.addLink(s1, s2)
    net.addLink(s2, h2)
    net.addLink(s1, s12)
    net.addLink(s12, s2)
    net.addLink(s0, s12)
 
    
    
    
    net.start() # demarrer le reseau, activer tous les hotes, commutateurs et controleur  
    

    
    
    CLI(net) # lancer une interface CLI pour tester le reseau
    net.stop() # apres la sortie de CLI arret du reseau et nettoyage

if __name__ == '__main__':
    setLogLevel('info') # definir le niveau de log à 'info' cad un niveau de detail modéré
    sdnsecTopo()
