
---

# **Challenge 7: input2 Solution Walkthrough**

## **Objective**
The goal of this challenge is to provide specific inputs through various input methods, including:

1. **Command-line arguments (ARGV)**
2. **Standard input/output (STDIN/STDERR)**
3. **Environment variables (ENV)**
4. **File manipulation**
5. **Network connection (TCP)**

To successfully complete the challenge, each input method must meet the conditions imposed by the binary.

---

## **Step 1: Setting up ARGV (Command-line Arguments)**

### **Conditions:**
The binary expects:
1. `argv` array should contain **100 elements**.
2. `argv['A']` (65th index) should be set to `\x00`.
3. `argv['B']` (66th index) should be set to `\x20\x0a\x0d` (space, newline, carriage return).

### **Solution:**
```c
char *new_argv[101];  // Declare 100 elements + NULL

// Fill argv with empty strings
for (int i = 0; i < 100; i++) {
    new_argv[i] = "";
}

// Add required elements
new_argv['A'] = "\x00";  // ASCII for 'A' = 65, NULL byte required
new_argv['B'] = "\x20\x0a\x0d";  // ASCII for 'B' = 66, inject required sequence

// Null-terminate the argv array
new_argv[100] = NULL;
```

---

## **Step 2: Handling Standard Input/Output (STDIN/STDERR)**

### **Conditions:**
The binary reads from standard input and error and expects:
- `stdin` to contain: `\x00\x0a\x00\xff`
- `stderr` to contain: `\x00\x0a\x02\xff`

### **Solution:**
```c
// Create and write to files for stdin and stderr redirection
int new_stdin = open("./first", O_RDWR | O_CREAT, 00777);
write(new_stdin, "\x00\x0a\x00\xff", 4);

int new_stderr = open("./second", O_RDWR | O_CREAT, 00777);
write(new_stderr, "\x00\x0a\x02\xff", 4);

// Reset file offsets to the beginning
lseek(new_stdin, 0, SEEK_SET);
lseek(new_stderr, 0, SEEK_SET);

// Redirect input/output streams
dup2(new_stdin, 0);  // Redirect standard input (stdin)
dup2(new_stderr, 2); // Redirect standard error (stderr)
```

---

## **Step 3: Environment Variable Injection**

### **Conditions:**
The binary checks for an environment variable with the key `\xde\xad\xbe\xef` and value `\xca\xfe\xba\xbe`.

### **Solution:**
```c
char *new_envp[2];
new_envp[0] = "\xde\xad\xbe\xef=\xca\xfe\xba\xbe";
new_envp[1] = NULL;  // Null-terminate the environment variable array
```

---

## **Step 4: File Creation and Writing**

### **Conditions:**
The binary attempts to open a file named `\x0a` (newline character) and expects it to contain `\x00\x00\x00\x00`.

### **Solution:**
```c
// Create and write the expected data to the file named "\x0a"
int newline = open("./\x0a", O_RDWR | O_CREAT, 00777);
write(newline, "\x00\x00\x00\x00", 4);
close(newline);
```

---

## **Step 5: Handling TCP Connection**

### **Conditions:**
The binary listens on the port provided in `argv['C']` and expects the value `\xde\xad\xbe\xef` to be sent via a TCP connection.

### **Solution:**
1. Set the required port in `argv`:
    ```c
    new_argv['C'] = "8080";
    ```

2. In a separate terminal, send the required input via netcat:
    ```bash
    python -c 'print '\xde\xad\xbe\xef'' | nc localhost 8080
    ```

---

## **Final Step: Executing the Binary**

Once all required input mechanisms are set up, we need to execute the binary with the prepared arguments and environment variables.

### **Solution:**
```c
execve("/path/to/input2", new_argv, new_envp);
```

---

## **Full Exploit Code**
Putting everything together:

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    // Step 1: Prepare ARGV
    char *new_argv[101];
    for (int i = 0; i < 100; i++) {
        new_argv[i] = "";
    }
    new_argv[100] = NULL;
    new_argv['A'] = "\x00";  // 65th element
    new_argv['B'] = "\x20\x0a\x0d";  // 66th element
    new_argv['C'] = "8080";  // Step 5: Set TCP port

    // Step 2: Handle standard input/output
    int new_stdin = open("./first", O_RDWR | O_CREAT, 00777);
    write(new_stdin, "\x00\x0a\x00\xff", 4);

    int new_stderr = open("./second", O_RDWR | O_CREAT, 00777);
    write(new_stderr, "\x00\x0a\x02\xff", 4);

    lseek(new_stdin, 0, SEEK_SET);
    lseek(new_stderr, 0, SEEK_SET);

    dup2(new_stdin, 0);  // Redirect stdin
    dup2(new_stderr, 2);  // Redirect stderr

    // Step 3: Set environment variables
    char *new_envp[2];
    new_envp[0] = "\xde\xad\xbe\xef=\xca\xfe\xba\xbe";
    new_envp[1] = NULL;

    // Step 4: Create required file
    int newline = open("./\x0a", O_RDWR | O_CREAT, 00777);
    write(newline, "\x00\x00\x00\x00", 4);
    close(newline);

    // Step 6: Execute binary with prepared arguments and environment
    execve("/path/to/input2", new_argv, new_envp);

    return 0;
}
```

---

## **Running the Exploit**

1. Compile the exploit code:
    ```bash
    gcc exploit.c -o exploit -w
    ```
2. Run the exploit:
    ```bash
    ./exploit
    ```
3. Open another terminal and send the TCP payload:
    ```bash
    python3 -c 'print("\xde\xad\xbe\xef")' | nc localhost 8080
    ```

---

## **Expected Output**
If all steps are executed correctly, you should see:

```
Congratulations! Here is your flag: FLAG{xxxxxxxx}
```

---

## **Key Takeaways**

1. **Understanding Input Sources in C Programs:**
   - ARGV (Command-line arguments)
   - STDIN/STDERR redirection
   - Environment variables
   - File manipulation
   - Network communication

2. **Working with System Calls:**
   - `open()`, `write()`, `lseek()`, `dup2()`, `execve()` are key system calls used in exploiting and interacting with binary programs.

3. **Practical Exploitation Approaches:**
   - Manipulating file descriptors and memory to bypass security checks.

---
