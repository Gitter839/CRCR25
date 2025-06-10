#!/usr/bin/env python3
import requests
import time
from Cryptodome.Util.number import long_to_bytes, bytes_to_long

def modify_ciphertext(ct_bytes, pos, orig_str, new_str):
    
    #the goal is to forge the cookie in order to modify the expire date (using xor manipulation)
    mod_ct = bytearray(ct_bytes)
    for i in range(len(orig_str)):
        diff = ord(orig_str[i]) ^ ord(new_str[i]) #difference betwwen the orignal char and the new char (that contain che new expire_date)
        mod_ct[pos + i] ^= diff # construct 1 byte at time the new cookie 
    return bytes(mod_ct) # return the forged cookie with the new expire_date

def main():
    BASE_URL = "http://130.192.5.212:6522"
    LOGIN_URL = BASE_URL + "/login"
    FLAG_URL  = BASE_URL + "/flag"
    
    sess = requests.Session()
    
    # Make the login with an username and admin = 1 , from the server code the condition admin = 1 si crucial otherwise we don't proced 
    # with admin = 1 the server gives us the nonce and the cookie, crucial elements to forge the cookie after 
    username = "AAAAAAA"
    params = {"username": username, "admin": "1"}

    r_login = sess.get(LOGIN_URL, params=params)
    

    data = r_login.json() # Get the data in JSON format 
    nonce_val = data["nonce"] #get the nonce 
    orig_cookie_int = int(data["cookie"]) # get the cookie in INT 
   
   
    
    # Cookie in Byte, in order to manipluate and construct the forged cookie 
    orig_cookie_bytes = long_to_bytes(orig_cookie_int)
    

    fixed_prefix = "username=" + username + "&expires=" #prefix
    offset = len(fixed_prefix) # after that offest, there is the value of the field expires
    
    #the server do : session['admin_expire_date'] = int(time.time()) - randint(10, 259) * 24 * 60 * 60
    #so it menas that the admin session exipre in a date that is the actual date - a random number of days between 10 and 259
    #(in the past)
    #In addition the serve compute the expire_date (used to construct the cookie) that is the acutal date + 30 days
    
    base_expires = int(time.time()) + 30 * 86400 # actual date + 30 days 
    orig_exp_str = str(base_expires)
    exp_length = len(orig_exp_str) # length of the expire_date field present in the cookie 
    
    

    
    #if 290 * 24 * 60 * 60 < abs(int(token["expires"]) - session['admin_expire_date']) < 300 * 24 * 60 * 60:
    #the server give us the flag only if the token["expires"]) - session['admin_expire_date'] is between 290 and 300 days 
    # the problem is that the session['admin_expire_date'] is unknonwn and is stored in the server side
    # the "expires" value is encrypted and present in the cookie, but we can forge it with xor manipulation 

    #in summary:
    #expires = actual_date + 30 days 
    #admin_expire_date = actual_date - X days (random X between 10 andn 259 days) unknown value
    # the server require that (expires - admin_expire_date) = (actual_date + 30 - actual_date + X) = 30 + x 
    # the server require that 30 + x is between 290 and 300 days
    # due to the fact that x is random and not knonw, we perform an intertion that graudally add a delta to the expire field present in the cookie and  try to enter in the
    # desiderd range 

    delta_found = None
    for delta in range(10000000, 30000000, 100000):
        new_expires_val = base_expires + delta
        new_exp_str = str(new_expires_val)
        if len(new_exp_str) != exp_length:
            continue  # Skip, the length is different so the exp_date is not consistent
        #forge the cookie 
        mod_ct = modify_ciphertext(orig_cookie_bytes, offset, orig_exp_str, new_exp_str)
        mod_cookie_int = bytes_to_long(mod_ct)
        
        #construct the json with the nonce and the forged cookie 
        params_flag = {"nonce": nonce_val, "cookie": str(mod_cookie_int)}
        r_flag = sess.get(FLAG_URL, params=params_flag)# contact the flag endpoint
        txt = r_flag.text.strip()
        print(f"Delta={delta} -> {txt}")
        
        if "OK! Your flag:" in txt: # check if the actual value of delta is enough and if the server give the flag 
            print(txt)
            delta_found = delta
            break
        
    

if __name__ == "__main__":
    main()
