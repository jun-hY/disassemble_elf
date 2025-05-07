# def convert_elf_to_hex(input_file, output_file):
#     with open(input_file, "rb") as f:
#         elf_data = f.read()  # ELF 파일 전체 읽기

#     # 16진수 변환 및 저장
#     with open(output_file, "w") as f:
#         for i in range(0, len(elf_data), 16):
#             chunk = elf_data[i:i+16]
#             hex_values = " ".join(f"{b:02x}" for b in chunk)
#             ascii_values = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
#             f.write(f"{i:08x}  {hex_values:<48}  {ascii_values}\n")  # 주소, HEX, ASCII 저장

#     print(f"Hex dump saved to {output_file}")

# # 사용 예제
# convert_elf_to_hex("./test", "output.hex")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import sys

def parse_elf_64(file_path):
    # 파일을 바이너리 모드로 열고 ELF 식별부 16바이트 읽기
    f = open(file_path, "rb")
    e_ident = f.read(16)
    
    print(e_ident)

    # 엔디안 설정 (1: 리틀 엔디안, 2: 빅 엔디안)
    if e_ident[5] == 1 :
        endian = "<"
    else:
        endian = ">"
    
    # 64비트 ELF 헤더 (e_ident 이후) 읽기
    elf_header_fmt = endian + "HHIQQQIHHHHHH"
    elf_header_size = struct.calcsize(elf_header_fmt)
    elf_header_data = f.read(elf_header_size)
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
     e_shnum, e_shstrndx) = struct.unpack(elf_header_fmt, elf_header_data)
    
    # 섹션 헤더 테이블 읽기
    sections = []
    f.seek(e_shoff)
    sh_fmt = endian + "IIQQQQIIQQ"
    for _ in range(e_shnum):
        section_data = f.read(e_shentsize)
        sh = struct.unpack(sh_fmt, section_data)
        sections.append(sh)
    
    # 섹션 이름 문자열 테이블 읽기
    shstr_section = sections[e_shstrndx]
    shstr_offset = shstr_section[4]
    shstr_size = shstr_section[5]
    f.seek(shstr_offset)
    shstr_data = f.read(shstr_size)
    
    # 모든 섹션 중 ".text" 섹션 찾기
    for idx, sec in enumerate(sections):
        sh_name_offset = sec[0]
        end_index = shstr_data.find(b'\x00', sh_name_offset)
        sec_name = shstr_data[sh_name_offset:end_index].decode("utf-8")
        if sec_name == ".text":
            sh_addr = sec[3]
            sh_offset = sec[4]
            sh_size = sec[5]
            print("섹션 인덱스:", idx)
            print("섹션 이름:", sec_name)
            print("가상 주소:", hex(sh_addr))
            print("파일 오프셋:", hex(sh_offset))
            print("섹션 크기:", sh_size, "바이트")
            break
    f.close()

if __name__ == "__main__":
    parse_elf_64(sys.argv[1])
