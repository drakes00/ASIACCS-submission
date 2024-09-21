n = 50


preambule = """
set preciseActions = true.

free c:channel.
free c_si:channel [private].
free c_se:channel [private].

type skey.
type OutPort.

(********** Equational Theory **************)
fun MAC(skey,bitstring):bitstring.
fun h(bitstring, bitstring): bitstring.
fun senc(bitstring,skey):bitstring.
reduc forall x:bitstring, k:skey; sdec(senc(x,k),k)=x.

(********** Events Declaration *************)
event SeqUniqueness(bitstring, nat).
event beginPayload(bitstring).
event endPayload(bitstring).
event sanitysi.
event sanityse.
event sanityc.
event error.

"""

restriction = """
(********** Restriction needed to guarentee uniqueness of sequence number *********************)
restriction st: bitstring, st': bitstring, alpha: nat; (event(SeqUniqueness(st, alpha)) && event(SeqUniqueness(st', alpha))) ==> st = st'.
"""

queries_sanity_checks = """
(********** Queries ***********************)
(***** Sanity Cheks *******)
query
  event(sanitysi);
  event(sanityse);
"""

query_payload_integrity = """
(*** Payload Integrity ****)
query p: bitstring;
  event(endPayload(p)) ==> event(beginPayload(p)).
"""

controller_declaration = """
(* Controller process *)
let ProcessController(ski: skey, ske: skey"""


controller_input ="""
    in(c_si, (p_encrypted: bitstring, n_s0: nat));
    let p = sdec(p_encrypted, ski) in

    (* Générer le FlowID et ExpTime *)
    new F: bitstring;
    new t: bitstring;

    let B = (F, t) in

    let C = (F, n_s0) in
    let PVFi = MAC(ski, C) in
    let FEi = B in
"""

controller_output_and_check="""
    out(c_si, y);
    in(c_se, (=F, xPVe: bitstring));
    if xPVe = PVFe then
       event sanityc
    else
      event error.
"""

keys_process_controller = ""
keys_main_types = ""
keys_controller_main = ""

process_si_payload_creation="""
(* Ingress Switch process *)
let ProcessSi(ski: skey) =
    in(c, n_s0: nat);
    new st[]:bitstring;
    event SeqUniqueness(st, n_s0);
    new p: bitstring;
    let p_encrypted = senc(p, ski) in
    event beginPayload(p);
    out(c_si, (p_encrypted, n_s0));
    in(c_si, y: bitstring);
"""

process_si_send ="""
    let B = (F, t) in
    let MACi = MAC(ski, B) in
    let C = (F, n_s0) in
    let PVFi = MAC(ski, C) in
    event sanitysi;
    out(c, (F, t, n_s0, PVFi"""

main_process ="""
(* Main Process *)
process
!( new ski: skey; new ske: skey; """

for i in range(1, n + 1):
  with open('SDNsec_payload_'+ str(i) + '.pv', 'a') as f:
    f.write(preambule)
    for k in range(1, i):
      f.write("event sanitys"+str(k)+".\n")
    f.write(restriction)
    f.write(queries_sanity_checks)
    for l in range(1, i):
      f.write("  event(sanitys"+str(l)+");\n")
    f.write("  event(sanityc).")
    f.write(query_payload_integrity + "\n")
    ports = "free egri, egre"
    for j in range(1, i):
      ports = ports + ", egr"+str(j)
    f.write(ports + ": OutPort.\n")
    if i > 1:
      keys_process_controller = keys_process_controller + ", sk"+str(i - 1)+ ": skey"
      keys_main_types = keys_main_types + "new sk"+str(i - 1)+ ": skey; "
      keys_controller_main =  keys_controller_main + ", sk"+str(i - 1)
    f.write(controller_declaration + keys_process_controller + ") = \n" + controller_input)
    first_message_plaintext = "(F, t"
    if i == 1:
      f.write("    let PVFe = MAC(ske, (PVFi, F, n_s0 + 1)) in \n")
      f.write("    let MACe = MAC(ske, (egre, FEi, B, n_s0, h(p, PVFi))) in\n")
      f.write("    let FEe = (egre, MACe) in\n")
      first_message_plaintext = first_message_plaintext + ", egre, MACe"
    else:
      for j in range(1, i + 1):
        if j == 1:
           first_message_plaintext = first_message_plaintext + ", egr1, MAC1"
           f.write("    let PVF1 = MAC(sk1, (PVFi, F, n_s0 + 1)) in \n")
           f.write("    let MAC1 = MAC(sk1, (egr1, FEi, B, n_s0, h(p, PVFi))) in\n")
           f.write("    let FE1 = (egr1, MAC1) in\n")
        elif (j == i):
           first_message_plaintext = first_message_plaintext + ", egre, MACe"
           f.write("    let PVFe = MAC(ske, (PVF"+str(i - 1)+", F, n_s0 + "+str(i)+")) in \n")
           f.write("    let MACe = MAC(ske, (egre, FE"+ str(i - 1)+", B, n_s0 + " + str(i - 1) +", h(p, PVF"+ str(i - 1)+"))) in\n")
           f.write("    let FEe = (egre, MACe) in\n")
        else:
          first_message_plaintext = first_message_plaintext + ", egr"+str(j)+", MAC"+str(j)
          f.write("    let PVF"+str(j)+" = MAC(sk"+str(j)+", (PVF"+str(j - 1)+", F, n_s0 + "+str(j)+")) in \n")
          f.write("    let MAC"+str(j)+" = MAC(sk"+str(j)+", (egr"+str(j)+", FE"+str(j - 1)+", B, n_s0 + " +str(j - 1)+", h(p, PVF"+str(j - 1)+ "))) in\n")
          f.write("    let FE"+str(j)+" = (egr"+str(j)+", MAC"+str(j)+") in\n")
    f.write("    let y = senc("+ first_message_plaintext +"), ski) in")
    f.write(controller_output_and_check)
    f.write(process_si_payload_creation)
    receive_message_plaintext = "(F: bitstring, t: bitstring"
    output_s0 = ""
    packet_entete = "(F: bitstring, t: bitstring, n_s: nat, PVFp: bitstring, p: bitstring"
    packet = ""
    if i == 1:
      receive_message_plaintext = receive_message_plaintext + ", xegre: OutPort, MACe: bitstring"
      output_s0 = output_s0 + ", xegre, MACe"
      packet = packet + ", xegre: OutPort, MACe: bitstring"
    else:
      for j in range(1, i + 1):
        if j == 1:
          receive_message_plaintext = receive_message_plaintext + ", xegr1: OutPort, MAC1: bitstring"
          output_s0 = output_s0 + ", xegr1, MAC1"
          packet = packet + ", xegr1: OutPort, MAC1: bitstring"
        elif (j == i):
          receive_message_plaintext = receive_message_plaintext + ", xegre: OutPort, MACe: bitstring"
          output_s0 = output_s0 + ", xegre, MACe"
          packet = packet + ", xegre: OutPort, MACe: bitstring"
        else:
          receive_message_plaintext = receive_message_plaintext + ", xegr"+str(j)+": OutPort, MAC"+str(j)+": bitstring"
          output_s0 = output_s0 + ", xegr"+str(j)+", MAC"+str(j)
          packet = packet + ", xegr"+str(j)+": OutPort, MAC"+str(j)+": bitstring"
    f.write("    let "+ receive_message_plaintext+ ") = sdec(y, ski) in\n")
    f.write(process_si_send + ", p")
    f.write(output_s0 + ")).\n\n")
    if i == 1:
      f.write("let ProcessSe(ske: skey) =\n")
      f.write("    in(c, "+ packet_entete + packet+"));\n")
      f.write("    let B = (F, t) in \n")
      f.write("    let FEi = (egri, B) in\n")
      f.write("    if (MACe = MAC(ske, (xegre, B, B, n_s, h(p, PVFp)))) then\n")
      f.write("         let n_s' = n_s + 1 in\n")
      f.write("         let PVFe = MAC(ske, (PVFp, F, n_s')) in\n")
      f.write("        event endPayload(p);\n")
      f.write("         event sanityse;\n")
      f.write("         out(c_se, (F, PVFe)).\n\n")
    else:
      for j in range(1, i + 1):
        if j == 1:
          f.write("let ProcessS1(sk1: skey) =\n")
          f.write("    in(c, "+ packet_entete + packet+"));\n")
          f.write("    let B = (F, t) in \n")
          f.write("    if (MAC1 = MAC(sk1, (xegr1, B, B, n_s, h(p, PVFp)))) then\n")
          f.write("        let n_s' = n_s + 1 in \n")
          f.write("        let PVF1 = MAC(sk1, (PVFp, F, n_s')) in \n")
          f.write("        event sanitys1;\n")
          f.write("        out(c, (F, t, n_s', PVF1, p" + output_s0 + ")).\n\n")
        elif j == i:
          f.write("let ProcessSe(ske: skey) =\n")
          f.write("    in(c, "+ packet_entete + packet+"));\n")
          f.write("    let B = (F, t) in \n")
          f.write("    let FE"+str(i - 1)+" = (xegr"+ str(i - 1) +", MAC"+ str(i-1) + ") in\n")
          f.write("    if (MACe = MAC(ske, (xegre, FE" +str(i - 1)+", B, n_s, h(p, PVFp)))) then\n")
          f.write("        let n_s' = n_s + 1 in \n")
          f.write("        let PVFe = MAC(ske, (PVFp, F, n_s')) in \n")
          f.write("        event endPayload(p);\n")
          f.write("        event sanityse;\n")
          f.write("        out(c_se, (F, PVFe)).\n\n")

        else:
          f.write("let ProcessS"+str(j)+"(sk"+str(j)+": skey) =\n")
          f.write("    in(c, "+ packet_entete + packet+"));\n")
          f.write("    let B = (F, t) in \n")
          f.write("    let FE"+str(j-1)+" = (xegr"+ str(j-1) +", MAC"+ str(j-1) + ") in\n")
          f.write("    if (MAC" + str(j)+ " = MAC(sk" + str(j)+ ", (xegr" + str(j)+ ", FE" +str(j - 1)+", B, n_s, h(p, PVFp)))) then\n")
          f.write("        let n_s' = n_s + 1 in \n")
          f.write("        let PVF" + str(j)+ " = MAC(sk" + str(j)+", (PVFp, F, n_s')) in \n")
          f.write("        event sanitys"+ str(j)+";\n")
          f.write("        out(c, (F, t, n_s', PVF"+ str(j)+", p" + output_s0 + ")).\n\n")

    f.write(main_process + keys_main_types + "\n\n")
    f.write("    (!ProcessController(ski, ske " + keys_controller_main + ")) |  (!ProcessSi(ski)) | (!ProcessSe(ske))")

    for j in range(2, i + 1):
      f.write("| (!ProcessS"+ str(j - 1) + "(sk"+ str(j - 1) + ")) ")

    f.write("\n )")
