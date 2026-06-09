+++
date = '2026-06-09T00:04:00+07:00'
draft = false
title = 'Linux Internal 101 - Part 1'
description = 'File mẫu mã nguồn C'
tags = ['technical']
+++
# Linux Internal 101 - Part 1

## Cấu trúc của một file ELF

File mẫu mã nguồn C

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- PHÂN BỔ BỘ NHỚ CHO CÁC SECTIONS --- */

// 1. Biến toàn cục chưa khởi tạo -> Sẽ được đưa vào section .bss
int global_uninit_var;

// 2. Biến toàn cục đã khởi tạo -> Sẽ được đưa vào section .data
int global_init_var = 0x1337BEEF;

// 3. Chuỗi hằng số (Read-Only) -> Sẽ được đưa vào section .rodata
const char* secret_message = "CONFIDENTIAL_PAYLOAD_STRING";

/* 4. Hàm phụ trợ -> Sẽ được đưa vào section .text */
void target_function(int a, int b) {
    int result = a ^ b; // Phép XOR cơ bản để dễ nhận diện khi đọc Assembly
    printf("[+] Target function executed. XOR Result: %d\n", result);
}

/* 5. Hàm Entry Point -> Sẽ được đưa vào section .text */
int main(int argc, char** argv) {
    // Biến cục bộ -> Nằm trên Stack (khi runtime), không nằm trong ELF sections
    int local_var = 42;

    printf("=== ELF Reference Binary ===\n");
    printf("[*] Data Section variable: 0x%X\n", global_init_var);
    printf("[*] Rodata Section string: %s\n", secret_message);
    
    // Gán giá trị để theo dõi trên debugger
    global_uninit_var = 100;

    target_function(local_var, 0x10);

    return 0;
}
```

Biên dịch tệp ELF để debug

```bash
gcc -g -O0 -o elf elf.c
```

### ELF Header

Nằm ngày offset `0x00` của file. Là bản đồ chỉ đường, cung cấp cho hệ điều hành thông tin cơ bản để quyết định xem có thể xử lý file này hay không.

* **Magic bytes**: 4 byte đầu tiên luôn là `7F 45 4C 46`. Kernel kiểm tra chữ ký này đầu tiên.
* **Class & Endianness**: 32-bit hay 64-bit, và thứ tự byte (little-endian hay big-endian).
* **e\_machine**: Kiến trúc vi xử lý đích: `EM_ARM` cho ARM 32-bit, `EM_AARCH64` cho ARM 64-bit, `EM_X86_64`.
* **e\_entry**: Địa chỉ bộ nhớ ảo  nơi luồng thực thi đầu tiên của chương trình sẽ bắt đầu.
* **Offsets**: Các con trỏ lưu vị trí của **Program Header Table** (PHT) và **Section Header Table** (SHT) bên trong file.

```bash
readelf -h elf                                                                                                [0]
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1080
  Start of program headers:          64 (bytes into file) # PHT
  Start of section headers:          15416 (bytes into file) # SHT
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         37
  Section header string table index: 36
```

### Program Header Table (PHT)

Kernel và trình liên kết động (linker) chỉ quan tâm đến bảng này thi thực thi file. PHT mô tả cách ánh xạ file vào không gian bộ nhớ ảo dưới dạng các Segments.

* `PT_LOAD`: Segment quan trọng nhất. Nó chứa các mã lệnh và dữ liệu thực sự cần thiết phải nạp vào RAM. Thường có ít nhất 2 `PT_LOAD`: một cho mã lệnh (quyền `RX`) và một cho dữ liệu (quyền `RW`).
* `PT_DYNAMIC`: Chứa các thông tin dành riêng cho dynamic linker (danh sách thư viện, địa chỉ bảng GOT/PLT).
* `PT_INTERP`: Chứa đường dẫn đến trình liên kết động.

### Section Header Table (SHT)

Compiler, Debugger và các công cụ dịch ngược (IDA Pro, Ghidra) quan tâm đến bảng này. PHT chia file thành các phần lớn để nạp vào RAM, trong khi SHT chia file thành các Sections chi tiết hơn để dễ quản lý về mặt logic.

Nhiều section có thể được nhóm chung vào một segment PT\_LOAD. Các section tiêu biểu:

* `.text`: Assembly của chương trình.
* `.rodata`: Dữ liệu chỉ đọc như hằng số, chuỗi hardcode.
* `.data`: Các biến toàn cục và biến tĩnh đã được khởi tạo giá trị ban đầu.
* `.bss`: Các biến toàn cục/tĩnh chưa được khởi tạo.
* `.symtab` & `.dynsym`: Bảng ký hiệu (Symbol tables). Lưu tên nguyên gốc của các hàm và biến.
* `.rel.plt` / `.rela.plt`: Thông tin phục vụ cho việc tái định vị và lazy binding (kết hợp với GOT/PLT).

```bash
readelf -l elf                                                                                                                                                                                                                       [0]

Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1080
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000678 0x0000000000000678  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000231 0x0000000000000231  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x00000000000001cc 0x00000000000001cc  R      0x1000
  LOAD           0x0000000000002db0 0x0000000000003db0 0x0000000000003db0
                 0x0000000000000270 0x0000000000000278  RW     0x1000
  DYNAMIC        0x0000000000002dc0 0x0000000000003dc0 0x0000000000003dc0
                 0x00000000000001f0 0x00000000000001f0  RW     0x8
  NOTE           0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000030 0x0000000000000030  R      0x8
  NOTE           0x0000000000000368 0x0000000000000368 0x0000000000000368
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_PROPERTY   0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000030 0x0000000000000030  R      0x8
  GNU_EH_FRAME   0x00000000000020c0 0x00000000000020c0 0x00000000000020c0
                 0x000000000000003c 0x000000000000003c  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002db0 0x0000000000003db0 0x0000000000003db0
                 0x0000000000000250 0x0000000000000250  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
   03     .init .plt .plt.got .plt.sec .text .fini
   04     .rodata .eh_frame_hdr .eh_frame
   05     .init_array .fini_array .dynamic .got .data .bss
   06     .dynamic
   07     .note.gnu.property
   08     .note.gnu.build-id .note.ABI-tag
   09     .note.gnu.property
   10     .eh_frame_hdr
   11
   12     .init_array .fini_array .dynamic .got

```

## Điều gì xảy ra khi thực thi một file elf

> Tạm thời bỏ qua phần load thư viện động.

#### Giai đoạn 1: Lời gọi hệ thống (The Syscall)

Khi chạy file, shell (bash/zsh) sẽ tạo ra một tiến trình con thông qua syscall `fork()` hoặc `clone()`. Sau đó, tiến trình con này gọi syscall `execve()`.

1. `execve(const char *pathname, char *const argv[], char *const envp[])`: Lệnh này báo cho Kernel biết: _"Hãy xóa sạch bộ nhớ của tiến trình hiện tại, nạp file nhị phân mới vào và chạy nó với các tham số, biến môi trường này."_
2. Kể từ thời điểm này, luồng thực thi chuyển từ User Space xuống Kernel Space (Ring 0).

#### Giai đoạn 2: Kernel tiếp nhận và Xác thực

Bên trong Kernel (đối với Linux là module `fs/exec.c` và `fs/binfmt_elf.c`), hệ điều hành bắt đầu phân tích file vật lý.

1. Kiểm tra quyền: Kernel kiểm tra xem file có quyền thực thi (`+x`) không, tiến trình gọi có đủ quyền truy cập file không (dựa trên UID/GID, SELinux policies).
2. Đọc Header: Kernel đọc 128 byte đầu tiên của file để xác định định dạng. Nếu nó thấy Magic Bytes là `\x7f ELF`, nó sẽ chuyển giao file cho hàm xử lý đặc thù là `load_elf_binary()`.
3. Xóa không gian cũ: Nếu định dạng hợp lệ, Kernel tiến hành giải phóng toàn bộ các trang nhớ (memory pages) của tiến trình cũ (cái đã gọi `execve`), chuẩn bị một "tờ giấy trắng" cho tệp ELF mới.

#### Giai đoạn 3: Ánh xạ bộ nhớ (Xây dựng Memory Layout)

Đây là giai đoạn Kernel đọc bảng Program Header Table (PHT)

1. Map các Segment `PT_LOAD`: \* Kernel đọc các phân đoạn `LOAD` và gọi hệ thống quản lý bộ nhớ ảo để ánh xạ mã lệnh (`.text`), dữ liệu (`.data`, `.rodata`) trực tiếp từ file trên ổ cứng vào RAM.
   * Nếu file có hỗ trợ PIE (Position Independent Executable), Kernel sẽ kích hoạt ASLR, tính toán một Base Address ngẫu nhiên và map các segment dựa trên độ lệch (offset) cộng với base address này.
2. Cấp phát BSS: Kernel cấp phát các trang nhớ ẩn danh (anonymous pages) cho phần chênh lệch giữa `MemSiz` và `FileSiz` của phân đoạn data, sau đó điền toàn số `0` (Zero-fill) để tạo ra section `.bss`.
3. Khởi tạo Stack & Tham số: Kernel tạo không gian Stack ở đỉnh của bộ nhớ ảo tiến trình. Nó đẩy các dữ liệu sau vào Stack theo thứ tự:
   * `envp`: Các biến môi trường.
   * `argv`: Các tham số dòng lệnh (ví dụ: `./elf`).
   * `argc`: Số lượng tham số.
   * Auxiliary Vectors (Auxv): Kernel đẩy các vector phụ trợ vào stack để chuyển thông tin phần cứng và hệ thống cho tiến trình. Trong số này có `AT_RANDOM` (16 bytes ngẫu nhiên được cấp bởi Kernel, dùng để tạo Stack Canary chống Buffer Overflow) và `AT_SYSINFO_EHDR` (địa chỉ của vDSO).

Ta dùng `strace` để xem thực tế những gì xảy ra

```bash
strace -e trace=execve,mmap,mprotect,arch_prctl ./elf                                                                                                                                                     [0]
execve("./elf", ["./elf"], 0x7ffed8602ea0 /* 77 vars */) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x737993779000
mmap(NULL, 79283, PROT_READ, MAP_PRIVATE, 3, 0) = 0x737993765000
mmap(NULL, 2170256, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x737993400000
mmap(0x737993428000, 1605632, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x737993428000
mmap(0x7379935b0000, 323584, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b0000) = 0x7379935b0000
mmap(0x7379935ff000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1fe000) = 0x7379935ff000
mmap(0x737993605000, 52624, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x737993605000
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x737993762000
arch_prctl(ARCH_SET_FS, 0x737993762740) = 0
mprotect(0x7379935ff000, 16384, PROT_READ) = 0
mprotect(0x5fe14e3fc000, 4096, PROT_READ) = 0
mprotect(0x7379937b1000, 8192, PROT_READ) = 0
=== ELF Reference Binary ===
[*] Data Section variable: 0x1337BEEF
[*] Rodata Section string: CONFIDENTIAL_PAYLOAD_STRING
[+] Target function executed. XOR Result: 58
+++ exited with 0 +++
```

{% hint style="info" %}
Trong output, có thể nhận ra rằng không có đoạn nào là load code của chính chương trình mà chỉ có load code của libc. Điều này là do việc load code chương trình được thực hiện chính bên trong `execve` ở kernel-space.&#x20;
{% endhint %}

Xem **Auxiliary Vectors**

```bash
LD_SHOW_AUXV=1 ./elf                                                                                                                                                                                      [0]
AT_SYSINFO_EHDR:      0x7ffeb53f4000
AT_MINSIGSTKSZ:       3632
AT_HWCAP:             bfebfbff
AT_PAGESZ:            4096
AT_CLKTCK:            100
AT_PHDR:              0x5f3855066040
AT_PHENT:             56
AT_PHNUM:             13
AT_BASE:              0x7011fb412000
AT_FLAGS:             0x0
AT_ENTRY:             0x5f3855067080
AT_UID:               1000
AT_EUID:              1000
AT_GID:               1000
AT_EGID:              1000
AT_SECURE:            0
AT_RANDOM:            0x7ffeb53dd089
AT_HWCAP2:            0x2
AT_EXECFN:            ./elf
AT_PLATFORM:          x86_64
AT_??? (0x1b): 0x1c
AT_??? (0x1c): 0x20
=== ELF Reference Binary ===
[*] Data Section variable: 0x1337BEEF
[*] Rodata Section string: CONFIDENTIAL_PAYLOAD_STRING
[+] Target function executed. XOR Result: 58

```

#### Giai đoạn 4: Trả quyền điều khiển (Return to User Space)

Khi ngôi nhà đã được xây xong, Kernel cần bàn giao lại chìa khóa.

1. Thiết lập Entry Point: Do chúng ta đang bỏ qua Dynamic Linker (`PT_INTERP`), Kernel sẽ nhìn thẳng vào trường `e_entry` trong ELF Header.
2. Cập nhật thanh ghi: Kernel ghi địa chỉ `e_entry` này vào thanh ghi Instruction Pointer (như `RIP` trên x86\_64). Nó cũng thiết lập thanh ghi Stack Pointer (`RSP`) trỏ tới đỉnh của Stack vừa tạo.
3. Context Switch: Kernel thực hiện chuyển ngữ cảnh, trả lại CPU về chế độ User Space. Mã lệnh đầu tiên của tệp nhị phân chính thức được thực thi.

#### Giai đoạn 5: Chuẩn bị Runtime ở User Space (C Runtime)

Một lầm tưởng phổ biến là `RIP` lúc này trỏ thẳng vào hàm `main()`. Thực tế là không. `e_entry` trỏ vào một hàm khởi tạo hệ thống tên là `_start` (được chèn vào bởi trình biên dịch, thường lấy từ file `crt1.o` của thư viện C tiêu chuẩn).

Quy trình cuối cùng diễn ra như sau:

1. `_start` thực thi: Nó thiết lập một số thanh ghi (như đưa `rbp` về 0 để đánh dấu đáy của chuỗi call stack).
2. Gọi `__libc_start_main`: Hàm `_start` thu thập `argc`, `argv` từ Stack và gọi hàm khởi tạo chính của thư viện C.
3. Thiết lập Canary và Thread: `__libc_start_main` lấy chuỗi ngẫu nhiên từ `AT_RANDOM` (Auxv) để khởi tạo giá trị Stack Canary cho thread chính. Thiết lập cơ chế đa luồng (nếu có) và đăng ký các hàm dọn dẹp bằng `atexit()`.
4. Gọi các hàm khởi tạo: Nó duyệt qua section `.init_array` và gọi toàn bộ các hàm constructor (nếu dev có định nghĩa các hàm với `__attribute__((constructor))`).
5. Vào Main: Cuối cùng, `__libc_start_main` gọi hàm `main(argc, argv)` của lập trình viên. Chương trình của bạn thực sự bắt đầu hoạt động. Kèm theo đó, khi `main()` kết thúc và `return`, `__libc_start_main` sẽ hứng giá trị trả về, gọi các hàm trong `.fini_array` để dọn dẹp, và cuối cùng gọi syscall `exit()` để báo cho Kernel tiêu hủy tiến trình.

#### Sử dụng GDB để debug xem chương trình thực tế

Load chương trình vào gdb và dùng command `starti` để chạy và dừng chương trình ngay tại `_start`

```bash
gdb -q ./elf                                                                                                                                                                                              [0]
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 15.1 in 0.00ms using Python engine 3.12
Reading symbols from ./elf...
gef➤  starti
Starting program: /tmp/elf

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.ubuntu.com>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.

Program stopped.
0x00007ffff7fe4540 in _start () from /lib64/ld-linux-x86-64.so.2
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x0
$rdx   : 0x0
$rsp   : 0x00007fffffffd9d0  →  0x0000000000000001
$rbp   : 0x0
$rsi   : 0x0
$rdi   : 0x0
$rip   : 0x00007ffff7fe4540  →  <_start+0000> mov rdi, rsp
$r8    : 0x0
$r9    : 0x0
$r10   : 0x0
$r11   : 0x0
$r12   : 0x0
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9d0│+0x0000: 0x0000000000000001   ← $rsp                                                        # argc = 1
0x00007fffffffd9d8│+0x0008: 0x00007fffffffddff  →  "/tmp/elf"                                                  # pointer argv[0]
0x00007fffffffd9e0│+0x0010: 0x0000000000000000                                                                 # NULL, end argv array
0x00007fffffffd9e8│+0x0018: 0x00007fffffffde08  →  "CHROME_DESKTOP=Termius.desktop"                            # pointer envp[0]
0x00007fffffffd9f0│+0x0020: 0x00007fffffffde27  →  "CLUTTER_DISABLE_MIPMAPPED_TEXT=1"
0x00007fffffffd9f8│+0x0028: 0x00007fffffffde48  →  "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/[...]"
0x00007fffffffda00│+0x0030: 0x00007fffffffde7e  →  "DEBUGINFOD_URLS=https://debuginfod.ubuntu.com "
0x00007fffffffda08│+0x0038: 0x00007fffffffdead  →  "DESKTOP_SESSION=ubuntu-xorg"
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7fe4533 <_dl_help+02c3>  call   0x7ffff7fd3cd0 <_dl_printf>
   0x7ffff7fe4538 <_dl_help+02c8>  jmp    0x7ffff7fe43d2 <_dl_help+354>
   0x7ffff7fe453d                  nop    DWORD PTR [rax]
 → 0x7ffff7fe4540 <_start+0000>    mov    rdi, rsp
   0x7ffff7fe4543 <_start+0003>    call   0x7ffff7fe51d0 <_dl_start>
   0x7ffff7fe4548 <_dl_start_user+0000> mov    r12, rax
   0x7ffff7fe454b <_dl_start_user+0003> mov    r13, rsp
   0x7ffff7fe454e <_dl_start_user+0006> mov    edx, DWORD PTR [rip+0x19b14]        # 0x7ffff7ffe068 <_rtld_global+4200>
   0x7ffff7fe4554 <_dl_start_user+000c> test   edx, 0x2
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "elf", stopped 0x7ffff7fe4540 in _start (), reason: STOPPED
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7fe4540 → _start()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤

```

Xem mã assembly của `_start`

```bash
gef➤  disassemble
Dump of assembler code for function _start:
=> 0x0000555555555080 <+0>:     endbr64
   0x0000555555555084 <+4>:     xor    ebp,ebp
   0x0000555555555086 <+6>:     mov    r9,rdx
   0x0000555555555089 <+9>:     pop    rsi
   0x000055555555508a <+10>:    mov    rdx,rsp
   0x000055555555508d <+13>:    and    rsp,0xfffffffffffffff0
   0x0000555555555091 <+17>:    push   rax
   0x0000555555555092 <+18>:    push   rsp
   0x0000555555555093 <+19>:    xor    r8d,r8d
   0x0000555555555096 <+22>:    xor    ecx,ecx
   0x0000555555555098 <+24>:    lea    rdi,[rip+0x101]        # 0x5555555551a0 <main>
   0x000055555555509f <+31>:    call   QWORD PTR [rip+0x2f33]        # 0x555555557fd8
   0x00005555555550a5 <+37>:    hlt
End of assembler dump.
```

Xóa thanh ghi `rdp` về `0`. Báo hiệu đáy call stack.

```
   0x000055555555508d <+13>:    and    rsp,0xfffffffffffffff0
   0x0000555555555091 <+17>:    push   rax
   0x0000555555555092 <+18>:    push   rsp
```

Chuẩn x86\_64 yêu cầu Stack phải luôn được căn lề 16-byte (địa chỉ kết thúc bằng 0) trước khi gọi bất kỳ hàm nào. Điều này là bắt buộc để các lệnh xử lý vector (SSE/AVX) bên trong thư viện `libc` hoạt động mà không bị lỗi _Segmentation Fault_. Phép toán `AND` với `0xfff...f0` làm tròn địa chỉ `rsp` xuống bội số của 16.

```
   0x0000555555555093 <+19>:    xor    r8d,r8d
   0x0000555555555096 <+22>:    xor    ecx,ecx
   0x0000555555555098 <+24>:    lea    rdi,[rip+0x101]        # 0x5555555551a0 <main>
```

Đoạn này chuẩn bị các thanh ghi để gọi hàm khởi tạo chính của thư viện C. Theo chuẩn gọi hàm (rdi, rsi, rdx, rcx, r8, r9):

```
0x000055555555509f <+31>:    call   QWORD PTR [rip+0x2f33]        # 0x555555557fd8
```

Nó gọi hàm `__libc_start_main` (thông qua bảng GOT).

## Sự khác biệt trên Android

### 1. Thư viện C chuẩn

Android sử dụng thư viện Bionic hay cho GNU C (glibc)

* Bionic được Google tối ưu cho thiết bị di động, dung lượng nhỏ hơn.
* Luồng khởi tạo: Khi tệp nhị phân native chạy, quá trình thiết lập môi trường C runtime khác với Linux tiêu chuẩn. Hàm `_start` sẽ thiết lập các thanh ghi tham số (trên ARM64 là `x0`, `x1` thay vì `rdi`, `rsi`) và gọi trực tiếp vào hàm `__libc_init` thay vì `__libc_start_main`.

### 2. Quy trình khởi tạo tiến trình (Zygote fork)

* Linux Native(`execve`): Yêu cầu Kernel phân bổ lại không gian bộ nhớ ảo mới từ đầu, ánh xạ tệp thực thi và gọi Linker để nạp các thư viện phụ thuộc.
* Android Application (Zygote): Android khởi chạy một tiến trình daemon tên là Zygote ngay khi boot. Zygote ánh xạ sẵn máy ảo (ART/Dalvik), Linker hệ thống và các thư viện framework cốt lõi (như `libc.so`, `libart.so`). Khi khởi động một ứng dụng mới, hệ thống gọi syscamm `fork()` từ tiến trình Zygote.
* Hệ quả phân tích: Tiến trình ứng dụng con kế thừa toàn bộ bộ nhớ của Zygote thông qua cơ chế Copy-on-Write (CoW). Điều này có nghĩa là base address của các thư viện hệ thống giống hệt nhau trên mọi tiến trình ứng dụng.

### 3. Cô lập bộ nhớ với Linker Namespaces

Bắt đầu từ Android 7.0 (API 24), Android triển khai cơ chế Linker Namespaces ở cấp độ trình liên kết động.

* Cơ chế hoạt động: Linker chia không gian tiến trình thành các namespace riêng biệt (ví dụ: Application Namespace và System Namespace) cùng với các quy tắc truy cập nghiêm ngặt.
* Ảnh hưởng kỹ thuật: Một tệp `.so` của ứng dụng không thể sử dụng `dlopen()` hoặc `dlsym()` để nạp hoặc lấy địa chỉ hàm từ các thư viện nội bộ của hệ thống (như `libart.so`). Trình liên kết sẽ từ chối yêu cầu truy cập xuyên namespace.
* Giải pháp trong Reverse Engineering: Để vượt qua giới hạn này trong quá trình viết các công cụ hooking (như Frida) hay module (như Xposed/LSPosed), lập trình viên phải đọc phân vùng `/proc/self/maps` để lấy địa chỉ cơ sở, sau đó tự viết logic phân tích cấu trúc ELF Header trên bộ nhớ (in-memory parsing) để tính toán offset của các symbol cần thiết.
