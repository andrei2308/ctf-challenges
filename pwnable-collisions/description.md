
---

# **Challenge: Hash Collision**

### **The Challenge Code**
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
    int* ip = (int*)p;
    int i;
    int res=0;
    for(i=0; i<5; i++){
        res += ip[i];
    }
    return res;
}

int main(int argc, char* argv[]){
    if(argc<2){
        printf("usage : %s [passcode]\n", argv[0]);
        return 0;
    }
    if(strlen(argv[1]) != 20){
        printf("passcode length should be 20 bytes\n");
        return 0;
    }

    if(hashcode == check_password(argv[1])){
        system("/bin/cat flag");
        return 0;
    }
    else
        printf("wrong passcode.\n");
    return 0;
}
```

---

### **Challenge Objective**

To reveal the flag, the program requires:
1. A **passcode** passed as an argument.
2. The passcode must be exactly **20 bytes long**.
3. The **check_password()** function must return a value equal to the predefined `hashcode` (**0x21DD09EC**).

When these conditions are met, the program executes:
```c
system("/bin/cat flag");
```

---

### **Code Analysis**

#### **`check_password()` Function**
1. **Input Handling**:
   - Takes a `char*` parameter (a string of bytes).
   - Treats the input as a series of integers by casting the pointer: `int* ip = (int*)p`.
   - This assumes the input string can be divided into 5 integers, each of **4 bytes**.

2. **Summing Integers**:
   - Iterates through the array, summing up the 5 integers (4 bytes each) into a variable `res`.

3. **Return Value**:
   - Returns the result of the summation.

#### **Key Observations**:
- **Passcode Length**:
  - The program enforces a **20-byte input length**:
    ```c
    if(strlen(argv[1]) != 20){
    ```
  - This ensures that exactly 5 integers (4 bytes each) can be created from the input string.

- **Hashcode Matching**:
  - To pass the `if` check:
    ```c
    if(hashcode == check_password(argv[1])){
    ```
    - The summation of the 5 integers must equal `0x21DD09EC`.

---

### **Plan to Solve**

To satisfy the condition `hashcode == check_password(argv[1])`, we need:
1. A 20-byte input that, when treated as 5 integers, sums up to `0x21DD09EC`.
2. **Convert `hashcode` to decimal**:
   ```c
   0x21DD09EC = 568134124
   ```
3. **Distribute the Sum**:
   - Split `568134124` into 5 integers. One simple way is:
     ```c
     568134124 = (4 * 113626824) + 113626828
     ```
4. **Convert to Hexadecimal**:
   - 113626824 = `0x6C5CEC8`
   - 113626828 = `0x6C5CECC`
5. **Convert to Little-Endian**:
   - In memory, integers are stored in **little-endian** format, so the bytes need to be reversed:
     - `0x6C5CEC8` → `\xC8\xCE\xC5\x06`
     - `0x6C5CECC` → `\xCC\xCE\xC5\x06`

6. **Build the Input**:
   - Construct a 20-byte input with 4 repetitions of `\xC8\xCE\xC5\x06` followed by `\xCC\xCE\xC5\x06`.

7. **Run the Program**:
   - Use the crafted input to reveal the flag.

---

### **Step-by-Step Solution**

#### **Step 1: Convert Hashcode to Decimal**
The given `hashcode` is:
```
0x21DD09EC = 568134124 (decimal)
```

#### **Step 2: Split into 5 Integers**
Divide the sum into 5 parts:
```
568134124 = (4 * 113626824) + 113626828
```

#### **Step 3: Convert to Hexadecimal**
Convert each integer into hexadecimal:
- `113626824` = `0x6C5CEC8`
- `113626828` = `0x6C5CECC`

#### **Step 4: Convert to Little-Endian**
Convert the hex values into little-endian format:
- `0x6C5CEC8` → `\xC8\xCE\xC5\x06`
- `0x6C5CECC` → `\xCC\xCE\xC5\x06`

#### **Step 5: Construct the Input**
Create a 20-byte input:
```
Input = "\xC8\xCE\xC5\x06" * 4 + "\xCC\xCE\xC5\x06"
```

#### **Step 6: Execute the Program**
Run the program with the crafted input:
```bash
./col `python -c 'print "\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06"'`
```

---

### **Validation**

#### **Why This Works**
1. **Sum of the Bytes**:
   - The first four integers are `113626824` each.
   - The last integer is `113626828`.
   - Their sum is:
     ```
     4 * 113626824 + 113626828 = 568134124 = 0x21DD09EC
     ```

2. **Little-Endian Format**:
   - The program treats the input as integers in little-endian format, so reversing the byte order ensures the values are interpreted correctly.

#### **Output**
If the input is correct, the program prints:
```
<contents of the flag>
```

---

### **Key Takeaways**

1. **Understanding Little-Endian**:
   - Knowing how integers are stored in memory is crucial for solving challenges involving binary representations.

2. **Hash Collision Technique**:
   - Dividing the hash value into parts that sum correctly is a common technique in CTFs.

3. **Memory Representation**:
   - Casting strings to integers (`int* ip = (int*)p`) allows manipulation of raw memory, a frequent approach in binary challenges.

---