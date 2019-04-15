Simple CLI 2-factor authenticator.

Use at own risk, not extensively tested so all keys are not guaranteed to work.

To install download rust and cargo and run:
```
cargo install
``` 
  
The binary will expect a stdin or argument of a base32 2fa key.

Below is an example of how to store secrets. However, you might want to encrypt them for some extra security. Storing the key on your system kind of defeats the purpose of 'something you have' so beware of the security implications and your threat models before storing them on your computer.
```
echo "github 65ZACCXCCXS6HXOFFD7ACXCCXLLA" >> ~/.keystore
echo "email 7AUSNEGACCXCCXS" >> ~/.keystore
```

Helper function in our terminal profile to fetch keys, pipe them to auth and copy the stdout into clipboard.
```bash
function 2fa() {
  grep "$1 " ~/.keystore |cut -f 2 -d " " |twofactorauth |xclip -selection clipboard
}
```
With above settings the below command gets the 6 digit code to your clipboard for the selected servicename.
```
2fa github
```
