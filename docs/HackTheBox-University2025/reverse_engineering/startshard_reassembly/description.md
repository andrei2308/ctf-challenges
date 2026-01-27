
---

# Starshard Reassembly

> **Description:** Twillie Snowdrop, the village's Memory-Minder, has discovered that one of her enchanted snowglobes has gone cloudy, its Starshard missing and its memories scrambled. To restore the scene within, you must provide the correct sequence of "memory shards". The binary will accept your attempt and reveal whether the Starshard glows once more. Can you decipher the snowglobe’s secret and bring the memory back to life?

## Initial Analysis

We are provided with a binary ELF file which we need to reverse. We upload the binary in Ghidra and see that it finds a `main.main` symbol. This makes it clear that we are dealing with a **Go compiled binary**.

Going into the `main` function, we see the following decompilation:

```c
/* WARNING: Removing unreachable block (ram,0x010a6f0b) */
/* ... (warnings truncated for brevity) ... */
/* Name: main.main
   Start: 010a6a60
   End: 010a7200 */

void main.main(void)

{
  undefined8 extraout_RAX;
  undefined8 extraout_RAX_00;
  runtime._type **pprVar1;
  long unaff_R14;
  undefined1 in_XMM15 [16];
  undefined1 local_338 [96];
  
  // ... [Variable Declarations Truncated] ...

  os.File *local_10;
  
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:179 */
  while (auStack_228[0] = in_XMM15._8_8_, local_338 <= *(undefined1 **)(unaff_R14 + 0x10)) {
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:179 */
    runtime.morestack_noctxt();
  }
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:182 */
  local_1d8 = &_go:itab.main.R0,main.MemoryRune;
  local_1d0 = &runtime.zerobase;
  local_1c8 = &_go:itab.main.R1,main.MemoryRune;
  
  // ... [Itab initializations for R2 through R27] ...

  local_28 = &_go:itab.main.R27,main.MemoryRune;
  local_20 = &runtime.zerobase;
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:188 */
  local_10 = os.Stdin;
  
  // ... [Buffer initialization] ...

                    /* /Users/kailash/Documents/November/go-chal/challenge.go:190 */
  local_298 = &datatype.String.string;
  local_290 = &PTR_DAT_010fa010;
                    /* /usr/local/Cellar/go/1.25.4/libexec/src/fmt/print.go:314 */
  fmt.Fprintln(&_go:itab.*os.File,io.Writer,os.Stdout,&local_298,1,1);
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:191 */
  local_2a8 = &datatype.String.string;
  local_2a0 = &goss_The_snowglobe_clouds..._Enter_the_scrambled_memory_to_restore_the_truth._10fa02 0;
                    /* /usr/local/Cellar/go/1.25.4/libexec/src/fmt/print.go:314 */
  fmt.Fprintln(&_go:itab.*os.File,io.Writer,os.Stdout,&local_2a8,1,1);
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:192 */
  local_2b8 = &datatype.String.string;
  local_2b0 = &goss_>__10fa030;
                    /* /usr/local/Cellar/go/1.25.4/libexec/src/fmt/print.go:272 */
  pprVar1 = &local_2b8;
  fmt.Fprint(&_go:itab.*os.File,io.Writer,os.Stdout,pprVar1,1,1);
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:194 */
  bufio.(*Reader).ReadString(&local_230,10);
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:195 */
  if (pprVar1 != (runtime._type **)0x0) {
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:196 */
    local_2c8 = &datatype.String.string;
    local_2c0 = &goss_The_memory_slipped_away..._10fa040;
                    /* /usr/local/Cellar/go/1.25.4/libexec/src/fmt/print.go:314 */
    fmt.Fprintln(&_go:itab.*os.File,io.Writer,os.Stdout,&local_2c8,1,1);
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:197 */
    return;
  }
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:199 */
  strings.TrimSpace(extraout_RAX_00,10);
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:201 */
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:202 */
  local_2d8 = &datatype.String.string;
  local_2d0 = &goss_The_snowglobe_stays_cloudy._10fa050;
                    /* /usr/local/Cellar/go/1.25.4/libexec/src/fmt/print.go:314 */
  fmt.Fprintln(&_go:itab.*os.File,io.Writer,os.Stdout,&local_2d8,1,1);
                    /* /Users/kailash/Documents/November/go-chal/challenge.go:203 */
  return;
}

```

We can see that much code is truncated by Ghidra. However, we see 27 references to `main.expected` and `main.match`. It is clear now that we are dealing with **Go interfaces**. This explains why the code appears truncated.

Our goal is to find the 27 `main.expected` functions, which will likely contain the expected values for every position in the flag.

## Finding the Shards

Looking into the function window in Ghidra, we see exactly 27 functions:

Going into the first one, `main.(*R0).Expected`, we see some strange code:

```c
/* Name: main.(*R0).Expected
   Start: 010a7200
   End: 010a7240 */

void main.(*R0).Expected(main.R0 *this)

{
  long *plVar1;
  main.R0 *extraout_RAX;
  long unaff_R14;
  
                    /* <autogenerated>:1 */
  plVar1 = *(long **)(unaff_R14 + 0x20);
  if (plVar1 != (long *)0x0) goto LAB_010a721f;
  while (this == (main.R0 *)0x0) {
    runtime.panicwrap();
    this = extraout_RAX;
LAB_010a721f:
    if ((undefined1 *)*plVar1 == &stack0x00000008) {
      *plVar1 = (long)&stack0xfffffffffffffff8;
    }
  }
  return;
}

```

Again, the code is truncated by Ghidra. It should return the expected value, but it cannot be analyzed effectively in the decompilation view. To solve this, we will look straight into the **assembly code** of the function.

### Assembly Analysis

```assembly
                             *************************************************************
                             * Name: main.(*R0).Expected                                 
                             * Start: 010a7200                                           
                             * End: 010a7240                                             
                             *************************************************************
                             void  __stdcall  main.(*R0).Expected (main.R0 * this )
             void             <VOID>         <RETURN>
             main.R0 *64      RAX:8          this
                             <autogenerated>:1
                             _main.(*R0).Expected                            XREF[2]:     main.main:010a70e7 (c) , 
                             main.(*R0).Expected                                          010fa838 (*)   
        010a7200 55              PUSH       RBP
        010a7201 48  89  e5       MOV        RBP ,RSP
        010a7204 4d  8b  66  20    MOV        R12 ,qword ptr [R14  + 0x20 ]
        010a7208 4d  85  e4       TEST       R12 ,R12
        010a720b 75  12           JNZ        LAB_010a721f
                             LAB_010a720d                                    XREF[2]:     010a7228 (j) , 010a722e (j)   
        010a720d 48  85  c0       TEST       this ,this
        010a7210 74  07           JZ         LAB_010a7219
        010a7212 b8  48  00       MOV        this ,0x48
                 00  00
        010a7217 5d              POP        RBP
        010a7218 c3              RET
                             LAB_010a7219                                    XREF[1]:     010a7210 (j)   
        010a7219 e8  42  73       CALL       runtime.panicwrap                                void runtime.panicwrap(void)
                 f6  ff
        010a721e 90              NOP
                             LAB_010a721f                                    XREF[1]:     010a720b (j)   
        010a721f 4c  8d  6c       LEA        R13 =>Stack [0x8 ],[RSP  + 0x10 ]
                 24  10
        010a7224 4d  39  2c  24    CMP        qword ptr [R12 ],R13
        010a7228 75  e3           JNZ        LAB_010a720d
        010a722a 49  89  24  24    MOV        qword ptr [R12 ],RSP
        010a722e eb  dd           JMP        LAB_010a720d
        010a7230 cc              ??         CCh
        ... (padding) ...

```

And bingo, we can see the key instruction:

```assembly
010a7212 b8 48 00    MOV    this, 0x48
         00 00

```

This is the value on the first position: **0x48**.

## Solution

We repeat the process for every function (R0 through R26), gather all the hex values, put them together, and then transform them to ASCII. This reveals the flag.

---