# 🎯 pwnable.kr Challenges

[← Back to Main](../)

Welcome to my pwnable.kr challenge solutions! This platform offers excellent binary exploitation challenges with progressive difficulty levels.

## 📊 Challenge Overview

**Platform:** [pwnable.kr](https://pwnable.kr)  
**Focus:** Binary Exploitation & System Security  
**Completed Challenges:** 10+  
**Difficulty Range:** Beginner to Advanced  

---

## 🏆 Completed Challenges

### 🟢 **Beginner Level**

#### [Buffer Overflow](./pwnable-bufferOverflow/description.md)
**Points:** 1  
**Category:** Stack-based buffer overflow  
**Skills:** Basic exploitation, shellcode injection

Classic buffer overflow challenge perfect for learning the fundamentals.

---

#### [Collision](./pwnable-collisions/description.md)
**Points:** 3  
**Category:** Hash collision  
**Skills:** Algorithm analysis, collision detection

Understanding hash functions and finding collisions in custom implementations.

---

#### [Flag](./pwnable-flag/description.md)
**Points:** 3  
**Category:** Reverse engineering  
**Skills:** Binary analysis, string extraction

Simple flag extraction challenge to practice basic reversing skills.

---

#### [Passcode](./pwnable-passcode/description.md)
**Points:** 10  
**Category:** Format string vulnerability  
**Skills:** Memory corruption, GOT overwrite

Learn format string exploitation and Global Offset Table manipulation.

---

### 🟡 **Intermediate Level**

#### [Random](./pwnable-random/description.md)
**Points:** 1  
**Category:** Predictable randomness  
**Skills:** PRNG analysis, predictability

Understanding pseudo-random number generators and their weaknesses.

---

#### [Input](./pwnable-input/description.md)
**Points:** 4  
**Category:** Input validation  
**Skills:** Multi-vector input, validation bypass

Complex challenge involving multiple input methods and validation mechanisms.

---

#### [Leg](./pwnable-leg/)
**Points:** 2  
**Category:** ARM assembly  
**Skills:** ARM architecture, assembly analysis

Introduction to ARM assembly language and architecture differences.

---

#### [Mistake](./pwnable-mistake/)
**Points:** 1  
**Category:** Logic error  
**Skills:** Code analysis, operator precedence

Finding logical mistakes in C code and exploiting them.

---

### 🔴 **Advanced Level**

#### [HorCruxes](./pwnable-horcruxes/)
**Points:** 7  
**Category:** Return-oriented programming  
**Skills:** ROP chains, advanced exploitation

Complex ROP chain construction in a Harry Potter themed challenge.

---

#### [Lotto](./pwnable-lotto/)
**Points:** 2  
**Category:** Probability manipulation  
**Skills:** Statistical analysis, logic exploitation

Understanding probability and finding ways to beat the odds.

---

## 📈 Learning Progression

### **Level 1: Foundation**
Start with basic challenges to understand core concepts:
1. [Flag](./pwnable-flag/) - Binary analysis basics
2. [Collision](./pwnable-collisions/) - Algorithm understanding
3. [Random](./pwnable-random/) - Predictability issues

### **Level 2: Exploitation**
Move to actual exploitation techniques:
1. [Buffer Overflow](./pwnable-bufferOverflow/) - Stack corruption
2. [Passcode](./pwnable-passcode/) - Format strings
3. [Input](./pwnable-input/) - Complex input handling

### **Level 3: Advanced Topics**
Master sophisticated techniques:
1. [HorCruxes](./pwnable-horcruxes/) - ROP chains
2. [Leg](./pwnable-leg/) - ARM exploitation
3. Advanced challenges (coming soon)

---

## 🛠️ Essential Tools

### **Static Analysis**
- **objdump** - Disassembly and binary analysis
- **readelf** - ELF file structure analysis
- **strings** - Extract printable strings
- **hexdump** - Hex analysis

### **Dynamic Analysis**
- **GDB** - GNU debugger with plugins
- **strace** - System call tracing
- **ltrace** - Library call tracing

### **Exploitation Framework**
- **pwntools** - Python CTF framework
- **ROPgadget** - ROP chain construction
- **one_gadget** - Magic gadget finder

### **Development**
- **Python** - Exploit development
- **C** - Understanding target code
- **Assembly** - Low-level analysis

---

## 💡 Key Techniques Learned

### **Memory Corruption**
- Stack buffer overflows
- Format string vulnerabilities
- Heap exploitation techniques
- Return-oriented programming (ROP)

### **Binary Analysis**
- ELF file format understanding
- Assembly language (x86, ARM)
- Debugging and dynamic analysis
- Static analysis techniques

### **System Security**
- ASLR bypass techniques
- NX bit circumvention
- Stack canary defeats
- GOT/PLT manipulation

---

## 🎯 Challenge Statistics

| Difficulty | Completed | In Progress | Total Available |
|-----------|-----------|-------------|-----------------|
| Toddler's Bottle | 8/19 | 2 | 19 |
| Rookie | 2/11 | 1 | 11 |
| Grotesque | 0/8 | 1 | 8 |
| Hacker's Secret | 0/? | 0 | ? |

---

## 🎓 Skills Developed

### **Technical Skills**
- Binary exploitation techniques
- Assembly language proficiency
- Debugging and reverse engineering
- Exploit development in Python

### **Security Mindset**
- Vulnerability identification
- Attack vector analysis
- Defense mechanism understanding
- Secure coding practices

---

## 📚 Recommended Reading

- **The Shellcoder's Handbook** - Advanced exploitation techniques
- **Hacking: The Art of Exploitation** - Fundamental concepts
- **Practical Binary Analysis** - Modern binary analysis
- **Intel x86 Manual** - Architecture reference

---

## 🔗 Useful Resources

- [pwnable.kr Official Site](https://pwnable.kr)
- [pwntools Documentation](https://docs.pwntools.com/)
- [GDB Tutorial](https://www.gdbtutorial.com/)
- [Assembly Guide](https://www.nasm.us/xdoc/2.14.02/html/nasmdoc0.html)

---

Ready to start your binary exploitation journey? Pick a challenge and dive in! 🚀
