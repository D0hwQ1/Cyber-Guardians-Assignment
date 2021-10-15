def decrypt_str(obf_str):
    des = list(obf_str)
    des_str = ""
    for i in des:
        other = ord(i)
        if other < ord("i") or other > ord("p"):
            if other < ord("r") or other > ord("y"):
                if other < ord("I") or other > ord("P"):
                    if other < ord("R") and other > ord("Y"):
                        other -= 9
                        des_str += chr(other)
                    else : des_str += chr(other)
                else:
                    other += 9
                    des_str += chr(other)
            else:
                other -= 9
                des_str += chr(other)
        else:
            other += 9
            des_str += chr(other)
    return des_str
 
def find_function_arg(addr):
    while True:
        addr = idc.prev_head(addr)
        if print_insn_mnem(addr) == "push":
            return get_operand_value(addr, 0)
    return ""
 
def get_string(addr):
    out = ""
    while True:
        if get_wide_byte(addr) != 0:
            out += chr(get_wide_byte(addr))
        else:
            break
        addr += 1
    return out
 
print("[*] Attempting to decrypt strings in malware")
for x in XrefsTo(0x10003b00, flags=0):
    ref = find_function_arg(x.frm)
    string = get_string(ref)
    deobf_string = decrypt_str(string)
    print('[STRING]:%s\n[Deobfuscated]:%s' % (string,deobf_string))
    set_cmt(x.frm, deobf_string,0)
    set_cmt(ref, deobf_string,0) 
    
    print("[ADDRESS] :"+hex(x.frm))
    ct = idaapi.decompile(x.frm)
    tl = idaapi.treeloc_t()
    tl.ea = x.frm
    tl.itp = idaapi.ITP_SEMI
    ct.set_user_cmt(tl,deobf_string)
    ct.save_user_cmts()