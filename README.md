# Library API
## This is a library API written by 4B
# API Documentation

**PUBLIC REGISTER**

* method- POST

* end point- /user/register

 * Description- The registration will succeed if the provided username is not already present in the database. The password is securely hashed using SHA-256, and the new user is assigned a role ID of 2 (User).


 **Example Requesst**

 POST /user/register

 ```
 {
  "username": "emerson",
  "password": "123"
}
```
**Response**

```
{
  "status": "success",
  "data": null
}
```

**UPDATE USER**

* method- POST

* end point- /user/auth

* Description- Authenticates a user by verifying the provided username and password. If the credentials are valid, the server generates a JWT token for the user to use for future authentication. The password is securely hashed using SHA-256.


 **Example Requesst**

 POST /user/auth

 ```
 {
  "username": "emerson",
  "password": "123"
}
```
**Response**

```
{
  "status": "success",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbGlicmFyeS5vcmciLCJhdWQiOiJodHRwOi8vbGlicmFyeS5jb20iLCJpYXQiOjE3MzE5ODE0MzYsImV4cCI6MTczMTk4NTAzNiwiZGF0YSI6eyJ1c2VyX2lkIjozMX19.KtXPG1jJwKCLWrlb73tGrtHc7Y5x5COq_JAYDyKfvpY",
  "data": null
}
```

