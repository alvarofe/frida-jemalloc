frida-jemalloc
==============

Module that parse jemalloc state to be used along with frida to inspect pointers. The whole thing has been based on shadow (https://github.com/CENSUS/shadow) where the code has been ported to typescript to be used with frida.

Usage
=====

```
npm install frida-jemalloc
```

```ts
import { Jemalloc } from "frida-jemalloc";

const jemalloc = new Jemalloc();
// After 20 times getting info of a pointer, parse again the whole thing
jemalloc.set_threshold(20);

const base = Module.findBaseAddress("module.so");

console.log("[*] Base of module " + base);

jemalloc.parse_all();

Interceptor.attach(base.add(...), {
  onEnter(args) {
    var ctx = this.context as Arm64CpuContext;
    jemalloc.get_info(ctx.x0).dump();
  }
});

```

```
[*] Jemalloc info of 0x7f5d8a5c00
 Chunk:
  Address : 0x7f5d800000
  Size    : 0x200000
 Run:
  Address : 0x7f5d8a5000
  Size    : 0x3000
 Region:
  Address : 0x7f5d8a5c00
  Size    : 0x600
[*] Jemalloc info of 0x7f539eb400
 Chunk:
  Address : 0x7f53800000
  Size    : 0x200000
 Run:
  Address : 0x7f539e9000
  Size    : 0x3000
 Region:
  Address : 0x7f539eb400
  Size    : 0x600
```

TODO
====

There are things still missing which will be added in the future. By now it only will work on Android8 64 bits as is the main device of testing I have, but more configurations can be added and hence tested. In addition, open to PR or whatever improvements.

