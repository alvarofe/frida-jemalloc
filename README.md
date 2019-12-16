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
import { getAndroidConfig } from "frida-jemalloc";

const jemalloc = new Jemalloc(getAndroidConfig());

// After 200 times getting info of pointers it will parse again the whole thing
jemalloc.setThreshold(200);

const base = Module.findBaseAddress("...");

// parse only handle chunks and run
// parseAll will include arenas and tcaches
jemalloc.parse();

console.log("[*] Base of module " + base);

Interceptor.attach(base.add(...), {
  onEnter(args) {
    var ctx = this.context as Arm64CpuContext;
    let info = jemalloc.getInfo(ctx.x0);

    if (info.region === null) {
      // Force the parsing because it should have been found
      jemalloc.parse();
      info = jemalloc.getInfo(ctx.x0);
    }

    info.dump();
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

The only configuration available is Android8 64 bits as is the main device of testing I have, but more configurations can be added. I am open to PR, comments or other improvements over the code.

