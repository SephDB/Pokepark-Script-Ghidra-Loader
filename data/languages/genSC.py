def argn(n:int):
    return 'arg'+str(n+1)

def argdef(n:int):
    return f"""local {argn(n)}:4;
    popSP({argn(n)});
    """

def getSC(n:int):
    return f""":SC{n} syscall_page:syscall_func is opcode=0x1 & subtype={n} & syscall_page & syscall_func {{
    {''.join(argdef(i) for i in range(n))}
    RES = SysCall(syscall_page:2,syscall_func:2,{','.join('arg'+str(i+1) for i in range(n))});
}}"""

with open('sc.sinc',mode='w') as sc:
    for n in range(1,9):
        sc.write(getSC(n))
        sc.write('\n')
