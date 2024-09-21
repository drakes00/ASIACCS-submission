# Implementation of SDNsec with Ryu and Mininet

## Working environment:
* Ubuntu MATE 20.04.6 LTS
* Ryu controller 4.43
* Python 3.12.2
* Mininet 2.3.0
* Wireshark 3.2.3

---------------------

## Files

### Normal function of SDNsec

* **topology.py:** The network topology script.
* **ryu_normal_function.py:** Script representing the normal function of SDNsec with PVF verification.
* **packet_that_does_not_include_hash_payload_in_MACs.py:** Script representing the packet with the SDNsec header sent by the controller to the ingress switch, without including the hash of the payload in the MAC calculation.

### Hash of the payload, the Hash of the PVf and the sequence number in MAC

* **ryu_attack_with_pvf_when_hash_payload_and_pvf_in_MAC.py:** Script that includes the hash of both the payload and the PVF in the MAC calculation.
* **packet_that_include_hash_payload_and_pvf_in_MACs.py:** Script representing the packet with the SDNsec header sent by the controller to the ingress switch, including both the hash of the payload and the PVF in the MAC calculation.

---------------------

## Scenarios

### NOTE:

After each execution of please dont forget to execute this commands : it clears any existing network topology, switches, controllers, and hosts from the Mininet environment. This is necessary to ensure that you start with a clean slate for your new network setup and helps avoid conflicts or issues caused by leftover configurations or processes from previous runs. 

1. `exit`
2. `sudo mn -c`

### Normal Function of SDNsec :

1. Launch the controller application using ryu-manager command : `ryu-manager ryu_normal_function.py`
2. Run the Mininet script to start the topology and connect it to the Ryu controller : `sudo python3 topology.py`
3. The Mininet shell will be opened
4. Try some commands like `mininet> nodes` to list all the nodes in the network and `mininet> links` to list all the links in the network, showing the connections between nodes and the interfaces they use.
5. In SDNsec, when a packet arrives at S0 (the ingress switch), the switch typically requests the controller to send the forwarding entries and all necessary information, including the flow ID,ExpTime, etc. To simplify our work, we customized the packet arriving at S0 to include all the required information calculated by the controller.
In the mininet shell execute this command to send the packet including SDNsec header to S0 : `mininet> h1 python3 packet_that_does_not_include_hash_payload_in_MACs.py`
6. Now see the result in the terminal or open wireshark and investigate the forwarding information transmitted through interfaces

### Attack to change the payload :

Here, we are in the case of PVF verification : an intermediate switch called S12 will change the payload without touching the SDNsec header.

1. Launch the controller application using ryu-manager command : `ryu-manager ryu_attack_with_pvf_verification_change_payload.py`
2. Run the Mininet script to start the topology and connect it to the Ryu controller : `sudo python3 topology.py`
3. The Mininet shell will be opened
4. In the mininet shell execute this command to send the packet including SDNsec header to S0 : `mininet> h1 python3 packet_that_does_not_include_hash_payload_in_MACs.py`
6. Now see the result in the terminal or open wireshark and investigate the forwarding information transmitted through interfaces

You will see in the terminal that the payload sent by S0 is not the same as the
payload recieved by S2. Although we are in the case of PVF verification this
alteration in the payload does not be detected by the controller.


## Inclusion of HASH(P || PVF || SeqNo) in MAC's calculation :

1. Launch the controller application using ryu-manager command : `ryu-manager ryu_attack_with_pvf_when_hash_payload_and_pvf_and_seqno_in_MACs.py`
2. Run the Mininet script to start the topology and connect it to the Ryu controller : `sudo python3 topology.py`
3. The Mininet shell will be opened
4. In the mininet shell execute this command to send the packet including SDNsec header to S0 : `mininet> h1 python3 packet_that_includ_hash_payload_and_pvf_and_seqno_in_MACs.py`
6. Now see the result in the terminal or open wireshark and investigate the forwarding information transmitted through interfaces

To verify this with the legitimate route and in the case of PVF verification,
simply change `egress_s0=3` to `egress_s0=2` (Line 176) and `egress_s1=3` to
`egress_s1=2` (line 265) in the code of
`ryu_attack_with_pvf_when_hash_payload_and_pvf_and_seqno_in_MACs.py`.










