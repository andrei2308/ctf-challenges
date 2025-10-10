Challenge name: alien-console
Description: You might not understand at first.

Flag format: ctf{sha256}

Goal: You have to connect to the service using telnet/netcat and find a way to recover the encoded message.

We netcat into the server, we are prompted for an input and then get a response. I didn't understand anything, but then I tried giving it more inputs and I saw that if I gave it several inputs the ouput would repeat.
![alt text](image.png)

The first bytes seem to remain the same so maybe a xor happens somewhere + the output is exactly what the flag size should be in hex.
I will try to input the first known chars of the flag: ctf{
![alt text](image-1.png)    
and as you can see we get 00... as the first bytes which means the output is a simple xor between the input and the flag.
We will write a script that will bruteforce the flag by trying different hex chars and append where the output is 0.
The flag is in this repository.
