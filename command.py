from readelf import ELF

class CMD :
    def __init__(self, f_name: str) :
        self.__e = ELF(f_name)
        self.__eh = self.__e.get_header()
        self.__sh = self.__e.get_s_header()
        self.__ph = self.__e.get_p_header()
        self.__sym = self.__e.get_sym()

        while(True) :
            userInput = input('$ ').split()
            self.__valifyUserInput(userInput)

    def __valifyUserInput(self, userInput: list[str]) : 
        if len(userInput) < 1 :
            return

        command = userInput[0].lower()
        argv = userInput[1:]

        if command == 'help' :
            self.__printManual()
        elif command == 'exit' :
            exit()
        elif command == 'info' :
            if argv[0] != 'sh' and argv[0] != 'eh' and argv[0] != 'ph' :
                print('plz input allowed argumanet')
                return
            if len(argv) < 1 :
                print('this command is require the argument! plz read `help`')
                return
            if argv[0] == 'eh' :
                self.__printEh()
            elif argv[0] == 'sh' :
                if len(argv) > 1:
                    if argv[1] == '-data' :
                        if argv[2] == '' : 
                            print('this command is require the argument! plz read `help`')
                            return
                        self.__printSecData(argv[2])
                        return
                    elif argv[1] != '' :
                        self.__printShByName(argv[1])
                else :
                    self.__printSh()
            elif argv[0] == 'ph' :
                if len(argv) > 1 :
                    if argv[1] == '-data' :
                        print('this option is not developed im working!')
                        return
                    elif argv[1] != '' :
                        self.__printPhByType(argv[1])
                else :
                    self.__printPh()
        elif command == 'disas' :
            if len(argv) < 1 :
                print('this command is require the argument! plz read `help`')
                return
            elif len(argv) > 1 :
                print('too many arguments')
                return
            if argv[0] == '-l' :
                self.__printFuncList()
            else :
                self.__printDisasFunc(argv[0])
        else :
            print(command+': command not found')
            print('plz read `help`')
            return

    def __printManual(self) :
        print(f'{'command list':-^88s}')
        print(f'info\teh\t\t\t- print elf header')
        print(f'\tsh\t[sh_name]\t- print section header or search section by section name')
        print(f'\t\t-data\t\t- print section data')
        print(f'\tph\t[ph_type]\t- prin t program header or search program by program type')
        print(f'\t\t-data\t\t- print program data - not yet')
        print(f'disas\t[func name]\t\t- disassmble function')
        print(f'\t-l\t\t\t- print allowed disassamble function list') 

    def __printEh(self) :
        print(f'{'':=<88s}')
        print(f'{'ELF Header':-^88s}')
        for key, value in self.__eh.items() :
            print(f'{key:<40s} @ {value}')
        print(f'{'':=<88s}')

    def __printSh(self) :
        print(f'{('Section info'):-^88s}')
        print(f'[Nr] {'Name':<16s} {'Type':<16s} {'Address':<16s} {'Offset':<8s}')
        print(f'     {'Size':<16s} {'EntSize':<16s} {'Flags':<7s}{'Link':<6s}{'Info':<6s}{'Align':<7s}')
        for i in self.__sh :
            print(f'[{self.__sh.index(i):>2d}]', end=' ')
            print(f'{(i['sh_name'][:12]+'[..]' if len(i['sh_name']) > 12 else i['sh_name']):<16s}', end=' ')
            print(f'{hex(i['sh_type'])[2:]:0>16s}', end=' ')
            print(f'{hex(i['sh_addr'])[2:]:0>16s}', end=' ')
            print(f'{hex(i['sh_offset'])[2:]:0>8s}')
            print(f'{'':5s}{hex(i['sh_size'])[2:]:0>16s}', end=' ')
            print(f'{hex(i['sh_entsize'])[2:]:0>16s}', end=' ')
            print(f'{hex(i['sh_flags'])[2:]:0>7s}', end='')
            print(f'{i['sh_link']:^6d}', end='')
            print(f'{i['sh_info']:<4d}', end=' ')
            print(f'{i['sh_addralign']:^7d}')

    def __printShByName(self, argv: str) :
        print(f'{('Section info'):-^88s}')
        print(f'[Nr] {'Name':<16s} {'Type':<16s} {'Address':<16s} {'Offset':<8s}')
        print(f'     {'Size':<16s} {'EntSize':<16s} {'Flags':<7s}{'Link':<6s}{'Info':<6s}{'Align':<7s}')
        for i in self.__sh :
            if i['sh_name'] == argv:
                print(f'[{self.__sh.index(i):>2d}]', end=' ')
                print(f'{(i['sh_name'][:12]+'[..]' if len(i['sh_name']) > 12 else i['sh_name']):<16s}', end=' ')
                print(f'{hex(i['sh_type'])[2:]:0>16s}', end=' ')
                print(f'{hex(i['sh_addr'])[2:]:0>16s}', end=' ')
                print(f'{hex(i['sh_offset'])[2:]:0>8s}')
                print(f'{'':5s}{hex(i['sh_size'])[2:]:0>16s}', end=' ')
                print(f'{hex(i['sh_entsize'])[2:]:0>16s}', end=' ')
                print(f'{hex(i['sh_flags'])[2:]:0>7s}', end='')
                print(f'{i['sh_link']:^6d}', end='')
                print(f'{i['sh_info']:<4d}', end=' ')
                print(f'{i['sh_addralign']:^7d}')

    def __printSecData(self, argv: str) :
        data = self.__e.get_section_by_name(argv)
        print(f'{(argv.lower()+' data'):-^88s}')
        for i in data :
            print(f'{i[0]:6s} : {' '.join(i[1:])}')

    def __printPh(self) :
        print(f'{('Program header'):-^88s}')
        print(f'{'  Type':<17s} {'Offset':<18s} {'VirtAddr':<18s} PhysAddr')
        print(f'{'':<17s} {'FileSiz':<18s} {'MemSiz':<18s}  {'Flags':<6s} Align')
        for i in self.__ph :
            print(f'  {i['ph_type']:<15s} 0x{i['ph_offset']:0>16x} 0x{i['ph_vaddr']:0>16x} 0x{i['ph_paddr']:0>16x}')
            print(f'  {'':<15} 0x{i['ph_filesz']:0>16x} 0x{i['ph_memsz']:0>16x}  {i['ph_flags']:^7x} 0x{i['ph_align']:<x}')
    
    def __printPhByType(self, argv: str) :
        print(f'{('Program header'):-^88s}')
        print(f'{'  Type':<17s} {'Offset':<18s} {'VirtAddr':<18s} PhysAddr')
        print(f'{'':<17s} {'FileSiz':<18s} {'MemSiz':<18s}  {'Flags':<6s} Align')
        for i in self.__ph :
            if i['ph_type'] == argv.upper() :
                print(f'  {i['ph_type']:<15s} 0x{i['ph_offset']:0>16x} 0x{i['ph_vaddr']:0>16x} 0x{i['ph_paddr']:0>16x}')
                print(f'  {'':<15} 0x{i['ph_filesz']:0>16x} 0x{i['ph_memsz']:0>16x}  {i['ph_flags']:^7x} 0x{i['ph_align']:<x}')

    def __printFuncList(self) :
        for sym in self.__sym :
            if sym['sym_type'] == 'FUNC' and sym['sym_shndx'] == 16 :
                print(sym['sym_name'])

    def __printDisasFunc(self, argv: str) :
        disasm = self.__e.get_disassmbled_func(argv)
        if disasm == None :
            print('plz input allowed arguments')
        for (address, size, mnemonic, op_str) in disasm :
            print(f'0x{address:x}\t{mnemonic}\t{op_str}')