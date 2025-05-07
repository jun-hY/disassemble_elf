from _io import BufferedReader
from capstone import *

kind_of_arch = {62:'x86-64'}
ph_type = {
1               : 'LOAD',
2               : 'DYNAMIC',
3               : 'INTERP',
4               : 'NOTE',
5               : 'SHLIB',
6               : 'PHDR',
7               : 'TLS',
0x60000000      : 'LOOS',
0x6fffffff      : 'HIOS',
0x70000000      : 'LOPROC',
0x7fffffff      : 'HIPROC',
}
ph_type[0x60000000 + 0x474e550]  = 'GNU_EH_FRAME'
ph_type[0x60000000 + 0x474e551]  = 'GNU_STACK'
ph_type[0x60000000 + 0x474e552]  = 'GNU_RELRO'
ph_type[0x60000000 + 0x474e553]  = 'GNU_PROPERTY'

stt_type = {
0 : 'NOTYPE',
1 : 'OBJECT',
2 : 'FUNC',
3 : 'SECTION',
4 : 'FILE',
5 : 'COMMON',
6 : 'TLS',
}
stb_type = {
0 : 'LOCAL',
1 : 'GLOBAL',
2 : 'WEAK',
}


class ELF :
    def __init__(self, fname):
        with open(fname, 'rb') as f :
            self.__e_ident = f.read(0x10)
            if self.__e_ident[:4] != b'\x7fELF' :
                exit('Not ELF file')
            self.__e_class = '32-bit' if self.__e_ident[4] == b'1' else '64-bit'
            self.__e_data = 'Little Endian' if self.__e_ident[5] != b'1' else 'Big Endian'
            self.__fname = fname
            if self.__e_class == '32-bit' :
                self.__parse_32_header(f)
            else :
                self.__parse_64_header(f)
                self.__parse_64_sec_header(f)
                self.__parse_64_sec_header_name(f)
                self.__parse_64_prog_header(f)
                self.__parse_64_f_symbol(f)
                self.__parse_64_sym_name(f)
    
    def __parse_32_header(self, f: BufferedReader) :
        f.seek(0x0)
        eh = f.read(0x24)
        pass

    def __parse_64_header(self, f: BufferedReader) :
        f.seek(0x10)
        eh = f.read(0x30)
        buf = {}
        buf['e_ident'] = self.__e_ident[:4].decode('utf-8')
        buf['e_class'] = self.__e_class
        buf['e_data'] = self.__e_data
        buf['e_type'] = bytes.hex(eh[:0x2][::-1])
        buf['e_machine'] = bytes.hex(eh[0x2:0x4][::-1])
        buf['e_version'] = int(bytes.hex(eh[0x4:0x8][::-1]), 16)
        buf['e_entry'] = int(bytes.hex(eh[0x8:0x10][::-1]), 16)
        buf['e_phoff'] = int(bytes.hex(eh[0x10:0x18][::-1]), 16)
        buf['e_shoff'] = int(bytes.hex(eh[0x18:0x20][::-1]), 16)
        buf['e_flags'] = int(bytes.hex(eh[0x20:0x24][::-1]), 16)
        buf['e_ehsize'] = int(bytes.hex(eh[0x24:0x26][::-1]), 16)
        buf['e_phentsize'] = int(bytes.hex(eh[0x26:0x28][::-1]), 16)
        buf['e_phnum'] = int(bytes.hex(eh[0x28:0x2a][::-1]), 16)
        buf['e_shentsize'] = int(bytes.hex(eh[0x2a:0x2c][::-1]), 16)
        buf['e_shnum'] = int(bytes.hex(eh[0x2c:0x2e][::-1]), 16)
        buf['e_shstrndx'] = int(bytes.hex(eh[0x2e:0x30][::-1]), 16)
        self.__eh = buf

    def __parse_64_sec_header(self, f: BufferedReader) :
        f.seek(self.__eh['e_shoff'])
        self.__sh_table = []
        for _ in range(self.__eh['e_shnum']) :
            sh = f.read(self.__eh['e_shentsize'])
            buf = {}
            buf['sh_name_off'] = int(bytes.hex(sh[:0x4][::-1]), 16)
            buf['sh_type'] = int(bytes.hex(sh[0x4:0x8][::-1]), 16)
            buf['sh_flags'] = int(bytes.hex(sh[0x8:0x10][::-1]), 16)
            buf['sh_addr'] = int(bytes.hex(sh[0x10:0x18][::-1]), 16)
            buf['sh_offset'] = int(bytes.hex(sh[0x18:0x20][::-1]), 16)
            buf['sh_size'] = int(bytes.hex(sh[0x20:0x28][::-1]), 16)
            buf['sh_link'] = int(bytes.hex(sh[0x28:0x2c][::-1]), 16)
            buf['sh_info'] = int(bytes.hex(sh[0x2c:0x30][::-1]), 16)
            buf['sh_addralign'] = int(bytes.hex(sh[0x30:0x38][::-1]), 16)
            buf['sh_entsize'] = int(bytes.hex(sh[0x38:0x40][::-1]), 16)
            self.__sh_table.append(buf)

    def __parse_64_prog_header(self, f: BufferedReader) :
        f.seek(self.__eh['e_phoff'])
        self.__ph = []
        for _ in range(self.__eh['e_phnum']) :
            ph = f.read(self.__eh['e_phentsize'])
            buf = {}
            buf['ph_type'] = ph_type[int(bytes.hex(ph[:0x4][::-1]), 16)]
            buf['ph_flags'] = int(bytes.hex(ph[0x4:0x8][::-1]), 16)
            buf['ph_offset'] = int(bytes.hex(ph[0x8:0x10][::-1]), 16)
            buf['ph_vaddr'] = int(bytes.hex(ph[0x10:0x18][::-1]), 16)
            buf['ph_paddr'] = int(bytes.hex(ph[0x18:0x20][::-1]), 16)
            buf['ph_filesz'] = int(bytes.hex(ph[0x20:0x28][::-1]), 16)
            buf['ph_memsz'] = int(bytes.hex(ph[0x28:0x30][::-1]), 16)
            buf['ph_align'] = int(bytes.hex(ph[0x30:0x38][::-1]), 16)
            self.__ph.append(buf)

    def __parse_64_sec_header_name(self, f: BufferedReader) :
        sh_text = self.get_s_header()[self.__eh['e_shstrndx']]
        f.seek(sh_text['sh_offset'])
        self.__text_data = f.read(sh_text['sh_size'])
        for i in range(self.__eh['e_shnum']) :
            n_off = self.__sh_table[i]['sh_name_off']
            end_idx = self.__text_data.find(b'\x00', n_off)
            sh_name = self.__text_data[n_off:end_idx].decode('utf-8')
            self.__sh_table[i]['sh_name'] = sh_name
    
    def __parse_64_sec_by_name(self, s_name) -> list[list] :
        for item in self.get_s_header() :
            if item['sh_name'] == s_name :
                break
        with open(self.__fname, 'rb') as f :
            f.seek(item['sh_offset'])
            s_data = []
            for i in range(0, item['sh_size']+1, 0x10):
                buf = f'{hex(i+item.get('sh_offset'))}'
                for j in range(0x10) :
                    if i+j >= item['sh_size'] : 
                        break
                    byte = f.read(0x1)
                    buf += (' '+bytes.hex(byte))
                s_data.append(buf.split())
        return s_data

    # add 0205
    def __parse_64_f_symbol(self, f: BufferedReader) :
        symtab = ''
        self.__sym = []
        for sh in self.get_s_header() :
            if sh['sh_name'] == '.symtab' :
                break
        f.seek(sh['sh_offset'])
        for _ in range(0, sh['sh_size'] // sh['sh_entsize']) :
            tmp = {}
            symtab = f.read(sh['sh_entsize'])
            tmp['sym_name'] = int.from_bytes(symtab[:0x4], (self.__e_data.split()[0]).lower())
            tmp['sym_info'] = stb_type[symtab[0x4] >> 4]
            tmp['sym_type'] = stt_type[symtab[0x4] & 0xf]
            tmp['sym_other'] = symtab[0x5]
            tmp['sym_shndx'] = int.from_bytes(symtab[0x6:0x8], (self.__e_data.split()[0]).lower())
            tmp['sym_value'] = int.from_bytes(symtab[0x8:0x10], (self.__e_data.split()[0]).lower())
            tmp['sym_size'] = int.from_bytes(symtab[0x10:0x18], (self.__e_data.split()[0]).lower())
            self.__sym.append(tmp)
    
    # add 0205
    def __parse_64_sym_name(self, f: BufferedReader) -> str :
        for st_text in self.get_s_header() :
            if st_text['sh_name'] == '.strtab' :
                break
        f.seek(st_text['sh_offset'])
        text_data = f.read(st_text['sh_size'])
        for i in range(len(self.__sym)) :
            n_off = self.__sym[i]['sym_name']
            end_idx = text_data.find(b'\x00', n_off)
            self.__sym[i]['sym_name'] = text_data[n_off:end_idx].decode('utf-8')
    
    # add 0205
    def find_program_address(self, start_addr: int, target_addr: int, size: int) -> str :
        buf = {}
        data = ''
        for i in self.get_p_header() :
            if i['ph_type'] == 'LOAD' :
                buf = i
                break
        offset = target_addr - start_addr
        with open(self.__fname, 'rb') as f :
            f.seek(buf['ph_offset']+offset)
            data = bytes.hex(f.read(size)[::-1])[-(size):]
        return data
        
    def get_header(self) -> dict :
        return self.__eh

    def get_s_header(self) -> list[dict] :
        return self.__sh_table
    
    def get_p_header(self) -> list[dict] :
        return self.__ph

    # add 0205
    def get_sym(self) -> list[dict] :
        return self.__sym
    
    # add 0205
    def get_section_by_name(self, s_name) -> list[list] :
        return self.__parse_64_sec_by_name(s_name)

    # add 0205
    # md.disasm_lite() -> tuple(address, size, mnemonic, op_str)
    def get_disassmbled_func(self, func: str)  :
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for st in self.__sym :
            if st['sym_name'] == func :
                break
        with open(self.__fname, 'rb') as f :
            f.seek(st['sym_value'])
            buf = f.read(st['sym_size'])
        return md.disasm_lite(buf, st['sym_value'])
