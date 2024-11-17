---

# **CTF Challenge: Breaking Spy Encryption**

---

## **Introduction**

A spy’s encrypted message has been intercepted, segmented into four parts. Each part employs RSA encryption, but the encryption contains specific vulnerabilities that allow us to break it. Your mission is to decrypt the message and uncover the spy’s secrets.

RSA, while a powerful encryption tool, depends heavily on secure key generation and implementation. This challenge demonstrates what happens when these best practices are ignored.

Let’s dive into the fascinating world of cryptanalysis!

---

## **Understanding RSA**

RSA encryption uses two keys: a **public key** (\(n, e\)) and a **private key** (\(d\)). Messages are encrypted using the public key and decrypted with the private key.

- **Encryption:** \(c = m^e \mod n\)
- **Decryption:** \(m = c^d \mod n\)

The private key \(d\) is derived from \(\phi(n)\), where \(\phi(n)\) depends on \(n = p \cdot q\), with \(p\) and \(q\) as the prime factors of \(n\). The challenge is to recover the plaintext message by identifying weaknesses in \(n\), \(e\), or their usage.

---

## **Challenge Breakdown**

### **Part 1: Short Modulus**

**Insight:** Reviewing the spy's source code, we discovered that \(p\) and \(q\) (the prime factors of \(n\)) are only 50 bits long. Such small primes make \(n\) trivial to factorize with tools like **FactorDB**.

Steps to solve:
1. Factorize \(n\) into \(p\) and \(q\).
2. Compute \(\phi(n) = (p-1)(q-1)\).
3. Calculate the private key \(d\) using the modular inverse of \(e\) modulo \(\phi(n)\).
4. Decrypt the ciphertext \(c\).

```python
from Crypto.Util.number import inverse, long_to_bytes, isPrime

n = 176305518861053382895557496760858663761
e = 65337
c = 125320009518574314085131240408571039166
p = 18245971932575253731
q = 9662709090672675131

phi_n1 = (p - 1)*(q - 1)
d1 = inverse(e, phi_n1)
m1 = pow(c, d1, n)
part1_flag = long_to_bytes(m1)
print(part1_flag)

```

**Decrypted Message:** **Securinets**

---

### **Part 2: Low Exponent**

**Insight:** The public exponent \(e = 3\) is unusually small. When the message \(m\) is small enough such that \(m^e < n\), the ciphertext \(c = m^e\) becomes easy to solve using the **Low Exponent Attack**.

Steps to solve:
1. Compute the cube root of \(c\) to recover \(m\).

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

c = 197417208202958143599631723743728746322656299361804759224701449690926123  
e = 3
m = iroot(c, e)[0]
message_part2 = long_to_bytes(m)

print(message_part2)
```

**Decrypted Message:** **{M4th5_ar3**

---

### **Part 3: Similar Primes**

**Insight:** The spy used primes \(p\) and \(q\) that are equal in value. This allows us to factor \(n\) by solving a simple quadratic equation.

**Solution**: We can use the square root approximation to find \(p\) and \(q\), since \(p\) and \(q\) are very close to each other. We can then factor \(n\) and decrypt the message.

```python
from Crypto.Util.number import inverse, long_to_bytes, isPrime
from math import isqrt

n = 24411368706839970460422754483201089662404107199576486613679807287258181726886214195935217848022125067449454844728575207204158365883648486693257408818026740525729180546292489452756861718918255439805424873829382727966373881591643790417947805476763934007722802649974230921474753324169237365715911245849137355670300457603531783861823844156959879225428473458146289836641826447620798779844052760877795382515655352428594152713415804675605963744959361322459192182269196981899611968948270092778051666639900167492484204073933318052353507618304328648512739790505194353401237309483547682611558070572232300016418476014581078111761
e = 65337
c = 17605388870161880089180341837216578272224133188253025300438920799447128743700230758280253665562537706091677584406546325553699668102396471120793922718645664177335717481892503997877052311221372017780438408459181607346677050160043636231614885787425139913947831063968438385420025401408618700423361556910665945237292341396617019394782619086369074081512242883960853354045635929689843217762179524850152109270719287804888254709867498969756654687757273380167563452195280171637884079264152506519932065539922912099574152984904618607122777683253782659089988385298632869842909001794006270574727782218745830809348523989278927486061
p = isqrt(n)

phi_n3 = p*(p - 1)
d3 = inverse(e, phi_n3)
m3 = pow(c, d3, n)
part3_flag = long_to_bytes(m3)
print(part3_flag)
```

**Decrypted Message:** **_actually_**

---

### **Part 4: \(n = p\)**

**Insight:** For this part, \(n\) is equal to p . This simplifies decryption as \(phi = n - 1\).

Steps to solve:
1. Calculate \(phi(n) = p - 1\).
2. Compute \(d\) as the modular inverse of \(e\) modulo \(phi\).
3. Decrypt the ciphertext.

```python
from Crypto.Util.number import inverse, long_to_bytes, isPrime
import math

n = 121200833690966776709060643822711050742985604446205669510725177299167867243911913976925989811560453455981711921853770440361384696937522926978137561742311077377004029613206028986961590224895043797922016723481410043592441059231424970233343588356488199307851553190702114713913653794899137216051867995276358187909
e = 65337
c = 61393465816570714619544589903427743707128302268541946339262805367681944147726237701878019858526148531735039584788460686998037516474231456927691539245624523030411879198280584350703983077152846327894834540929594780847071450267332591373983505894012713688089673176251732541010903363685599872166893790830896693527
p = n

phi_n4 = (p - 1) 
d4 = inverse(e, phi_n4)
m4 = pow(c, d4, n)
part1_flag = long_to_bytes(m4)
print(part1_flag)
```

**Decrypted Message:** **super_fun**

---

## **Final Flag**

Combine all parts of the message to reveal the final flag.

```python
final_flag = "Securinets" + "{M4th5_ar3" + "_actually_" + "super_fun"
print("Final Flag:", final_flag)
```

**Final Flag:** **Securinets{M4th5_ar3_actually_super_fun}**

---

## **Conclusion**

This challenge highlights critical RSA vulnerabilities:
1. **Short modulus** exposes weak primes to factorization.
2. **Low exponent** simplifies ciphertext cracking.
3. **Similar primes** compromise security through predictable factorization.
4. **Prime modulus** simplifies decryption due to weak key generation.

Each part emphasized the importance of secure key generation and implementation. Always ensure your cryptographic systems follow best practices to safeguard against such exploits.
