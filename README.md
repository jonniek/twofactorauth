Simple CLI 2-factor authenticator.

To install download rust and cargo and run:
```
cargo install
``` 
  
The binary will expect a stdin or argument of a base32 2fa key. Below is some useful scripts to use in combination with the binary.

Create name key pairs in a file separated by space
```
echo "servicename 65ZACCXCCXS6HXOFFD7ACXCCXLLA" >> ~/.keystore
echo "servicename2 7AUSNEGACCXCCXS" >> ~/.keystore
```

Create a helper function in our terminal profile to fetch keys, pipe them to auth and copy the stdout into clipboard.
```bash
function 2fa() {
  grep "$1 " ~/.keystore |cut -f 2 -d " " |twofactorauth |xclip -selection clipboard
}
```
With above settings the below command gets the 6 digit code to your clipboard for the selected servicename.
```
2fa servicename
```