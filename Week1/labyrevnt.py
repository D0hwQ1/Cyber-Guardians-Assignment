i = 0x59be5
out = ""

def get_chr(addr):
    global out
    print("test(addr)", hex(addr))
    addr = idc.prev_head(addr)
    print("test(get_chd)", hex(addr))
    out += chr(get_operand_value(addr, 1))
    addr = get_func_attr(addr, FUNCATTR_START)
    print("test2(get_chd)", hex(addr))
    return addr

def get_logic(addr):
    for addr in XrefsTo(idc.prev_head(addr), flags=0):
        print("test(get_logic)", hex(addr.frm))
            
        return addr.frm
    return 0;

def not_logic(addr):
    global out
    arrive = idc.prev_head(addr)
    print("arrive", hex(arrive))

    while True:
        addr = idc.prev_head(addr)
        if print_insn_mnem(addr) == "sub":
            sub_offset = get_operand_value(addr, 1)

            while True:
                addr = idc.next_head(addr)
                if print_insn_mnem(addr) == "cdqe":
                    break

            addr = idc.next_head(addr)
            rdx = get_operand_value(addr, 1)
            rax = arrive - rdx
            rax = 0x100000000 + rax
            print("rax", hex(rax))

            addr = idc.prev_head(addr)
            addr = idc.prev_head(addr)
            addr = idc.prev_head(addr)

            prev_rax = get_operand_value(addr, 1)
            print(hex(prev_rax))

            cnt = 0
            # while True:
            while True:
                if get_wide_dword(prev_rax) == rax:
                    rdx = int(cnt / 4)
                    print("rdx", hex(rdx))
                    break
                else:
                    print("prev_rax", prev_rax)
                    prev_rax += 1
                    cnt += 1
                    print("cnt", cnt)

            eax = rdx + sub_offset
            print("eax", hex(eax))
            out += chr(eax)
            addr = get_func_attr(addr, FUNCATTR_START)

            return addr

while i != 0x625b:
    for x in XrefsTo(i, flags=0):
        print("main", hex(x.frm)) 
        addr = get_logic(x.frm)
        if addr == 0:
            i = not_logic(x.frm)
        else:
            i = get_chr(addr)
        print("try(i)", hex(i))
        break;
        # except:
        #     i = not_logic(x.frm)
        #     print("except(i)", hex(i))
        #     break;

print(out[::-1])
