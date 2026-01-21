
# Reverse Write-up (ELF x86-64) — Recover Password/Flag via Stack-Encoded String + XOR Decoder

## 1. Overview
https://tryhackme.com/room/reverselfiles
Crackme4

Challenge là một ELF x86-64 kiểm tra password theo flow:

- Chạy chương trình với 1 tham số `password`
- Nếu đúng → in `password OK`
- Nếu sai → in `password "%s" not OK`

Trong bài này, **flag chính là password đúng**.

---

## 2. Program Flow Analysis

### 2.1. `main(argc, argv)`

Quan sát disassembly:

- Nếu `argc != 2` → in usage và thoát
- Nếu `argc == 2` → gọi:

```asm
compare_pwd(argv[1])
````

=> Mọi logic xác thực nằm trong `compare_pwd()`.

---

## 3. Core Logic: `compare_pwd(user_input)`

### 3.1. Dựng “password thật” trên stack (obfuscated)

Trong `compare_pwd()`, chương trình **không** dùng password plaintext trong `.rodata`. Thay vào đó, nó ghi các hằng số trực tiếp vào stack:

```asm
mov rax, 7B175614497B5D49h
mov qword ptr [rbp+s1], rax

mov rax, 547B175651474157h
mov [rbp+var_18], rax

mov word ptr [rbp+var_10], 4053h
mov [rbp+var_10+2], 0      ; null terminator
```

Sau đó:

```asm
lea rax, [rbp+s1]
mov rdi, rax
call get_pwd
```

Cuối cùng:

```asm
strcmp(s1, user_input)
```

=> Kết luận: `s1` là buffer chứa **chuỗi bị encode/obfuscate**, `get_pwd()` là hàm **decode in-place**, rồi đem so sánh với input.

---

## 4. Recover Encoded String (Endianness)

### 4.1. Little-endian trên x86-64

Các `qword` constants nằm trong bộ nhớ theo **little-endian**.

* `0x7B175614497B5D49` → bytes trong RAM:

  * `49 5D 7B 49 14 56 17 7B`

* `0x547B175651474157` → bytes trong RAM:

  * `57 41 47 51 56 17 7B 54`

* `0x4053` → bytes:

  * `53 40`

Ghép chuỗi theo layout stack + null terminator `00`:

```
49 5D 7B 49 14 56 17 7B 57 41 47 51 56 17 7B 54 53 40 00
```

Đổi sang dạng ASCII (giữ byte không in được dưới dạng `\x..`) ta được chuỗi đáng nghi:

```
I]{I\x14V\x17{WAGQV\x17{TS@
```

Đây là **encoded password** trước khi decode.

---

## 5. Decode Routine: `get_pwd()`

Disassembly cho thấy `get_pwd()` là một vòng lặp XOR:

```asm
add [rbp+var_4], 1
...
movzx eax, byte ptr [rax]   ; al = buf[i]
test  al, al                ; stop at '\0'
jnz   loc_40063E

loc_40063E:
movzx eax, byte ptr [rax]   ; al = buf[i]
xor   eax, 24h              ; al ^= 0x24
mov   [rdx], al             ; buf[i] = al (in-place)
```

Pseudo-code tương đương:

```c
void get_pwd(uint8_t *buf) {
    for (int i = 0; buf[i] != 0; i++)
        buf[i] ^= 0x24;
}
```

=> Đây là **single-byte XOR obfuscation** với key `0x24`.

---

## 6. Recover Plaintext Password (Flag)

Áp dụng XOR `0x24` lên từng byte của chuỗi:

```
"I]{I\x14V\x17{WAGQV\x17{TS@" XOR 0x24
```

Ví dụ minh hoạ vài byte đầu:

* `'I'` (0x49) ^ 0x24 = 0x6D = `'m'`
* `']'` (0x5D) ^ 0x24 = 0x79 = `'y'`
* `'{'` (0x7B) ^ 0x24 = 0x5F = `'_'`

Tiếp tục toàn bộ chuỗi thu được plaintext:

```
my_m0r3_secur3_pwd
```

Vì đề xác nhận **flag chính là password**, nên:

**FLAG = `my_m0r3_secur3_pwd`**

---

## 7. Verification

Chạy chương trình:

```bash
./chall my_m0r3_secur3_pwd
```

Kỳ vọng:

* `password OK`
