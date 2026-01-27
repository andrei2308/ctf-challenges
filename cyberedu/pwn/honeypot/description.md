
---

# Honeypot Challenge Writeup

## Vulnerability Analysis

The challenge is a logic puzzle involving **Random Number Generator (RNG) Prediction** and **Race Conditions** (or precise state management) between the main process and a spawned thread.

1. **Predictable RNG**: The program seeds the random number generator with `time(NULL)` at the start of `main`.
```c
seed = time((time_t *)0x0);
srand((uint)seed);

```


Since we know the server's time (roughly), we can seed our own local RNG in the exploit script to perfectly predict every `rand()` call.
2. **Thread Interaction**: When Option 3 is selected:
* A background thread (`FUN_00400fab`) is spawned. This thread accesses the global firewall state variable (`DAT_006020dc`) and calls `rand()`.
* The main thread executes `FUN_00401010`, which *also* calls `rand()` to determine the attack type.



## Exploit Steps

The goal is to survive enough rounds to flag the challenge. To do this, we must block every attack while ensuring the background thread executes its logic correctly.

### 1. Syncing the RNG

We load the standard C library (`libc`) in our Python script and call `srand(time(0))` immediately before connecting. This synchronizes our random sequence with the server's.

### 2. The "Bait and Switch" Strategy

To survive a round, we have to manage the global `firewall` variable so it satisfies *both* the background thread and the main thread, which run almost simultaneously.

* **Step A: Set Bait (Option 2)**
We use Option 2 to set the global firewall state to `1`. This prepares the state for the background thread that is about to launch.
* **Step B: Predict (Local Simulation)**
In our script, we simulate the RNG consumption:
1. `thread_burn = libc.rand()`: This value accounts for the `rand()` call made by the background thread.
2. `attack_val = libc.rand() & 3`: This is the attack type the main thread will generate.


* **Step C: Trigger & Switch (Option 3)**
We select Option 3.
1. The thread spawns and reads our "Bait" (Firewall=1).
2. The main thread immediately asks for *new* firewall input.
3. We send the `attack_val` we predicted in Step B.



By updating the firewall variable just in time, we successfully block the main attack (matching `attack_val`) while having allowed the thread to see the previous state. Repeating this loop allows us to survive indefinitely/until the win condition is met.