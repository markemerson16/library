# Library API
## This is a library API written by 4B
# API Documentation



#public register

method- POST

end point- /user/register

 Description- The registration will succeed if the provided username is not already present in the database. The password is securely hashed using SHA-256, and the new user is assigned a role ID of 2 (User).
 ```
 Example Requesst

 POST /user/register

 ```
 {
  "username": "estaciodave",
  "password": "332"
}
```

