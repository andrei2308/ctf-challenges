
---

# **Challenge 6: Random Key**

### **Challenge Code**
```c
int main() {
    unsigned int random;
    random = rand();        // random value!

    unsigned int key = 0;
    scanf("%d", &key);

    if ((key ^ random) == 0xdeadbeef) {
        printf("Good!\n");
        system("/bin/cat flag");
        return 0;
    }

    printf("Wrong, maybe you should try 2^32 cases.\n");
    return 0;
}
```

---

### **Challenge Objective**
To obtain the flag, the program must satisfy the condition:
```c
(key ^ random) == 0xdeadbeef
```

To achieve this:
1. Determine the value of `random`, which is generated at runtime using the `rand()` function.
2. Calculate the required `key` value based on `random`.
3. Input the calculated `key` into the program to reveal the flag.

---

### **Key Observations**

1. **Behavior of `rand()`**:
   - The `rand()` function in C generates pseudo-random numbers.
   - By default, `rand()` starts with the **same seed** (usually `1`) unless explicitly initialized with `srand()`.
   - This means the sequence of random numbers is **predictable** if `srand()` is not used.

2. **The Key Formula**:
   The relationship between `key` and `random` is:
   ```c
   key = random ^ 0xdeadbeef
   ```
   Using the generated value of `random`, we can calculate the required `key`.

---

### **Step-by-Step Solution**

#### **Step 1: Replicate the Random Number Locally**
Write a simple C program to replicate the `rand()` function and extract the first random value:
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned int random = rand(); // Default seed (no srand)
    printf("Random: %u\n", random);
    return 0;
}
```

1. Compile and run the program:
   ```bash
   gcc random_generator.c -o random_generator
   ./random_generator
   ```
2. The output will give the value of `random` (e.g., `1804289383`).

---

#### **Step 2: Calculate the Key**
Using the value of `random`, calculate the required `key` in Python:
```python
# Replace 1804289383 with the actual random value from the above program
random = 1804289383
key = random ^ 0xdeadbeef
print(f"The key is: {key}")
```

1. Save this code to a file (e.g., `generate_key.py`).
2. Run the script:
   ```bash
   python3 generate_key.py
   ```
3. It will print the calculated key:
   ```
   The key is: 568134134
   ```

---

#### **Step 3: Run the Challenge Program**
1. Run the provided challenge binary:
   ```bash
   ./random
   ```
2. Input the key obtained from the Python script (e.g., `568134134`).
3. If the key is correct, the program will print:
   ```
   Good!
   <flag>
   ```

---

### **Detailed Explanation**

#### **Predicting `rand()`**:
The challenge exploits the fact that `rand()` generates a deterministic sequence of numbers if `srand()` is not used. The first call to `rand()` always returns the same value for a given platform and compiler configuration.

#### **How the Key Works**:
1. The program checks:
   ```c
   if ((key ^ random) == 0xdeadbeef)
   ```
2. Rearranging:
   ```c
   key = random ^ 0xdeadbeef
   ```
3. By calculating `key` with the known value of `random`, you ensure the condition evaluates to true.

---