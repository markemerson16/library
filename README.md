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

**USER AUTHENTICATION**

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


**USER UPATE**

* method- PUT

* end point- /user/update

 * Description-  Allows an authenticated user to change their username and password. The user must provide the old username and old password and the new username and new password. The old username and old password is checked, and if it matches the current username and current password, it is updated to the new one. A new JWT token is generated for the user after the password change, and the old token is marked as used.


 **Example Requesst**

 PUT /user/auth

 ```
 {
  "username":"emerson",
  "new_username":"markemerson",
  "new_password":"1234"
}
```
**Response**

```
{
  "status": "success",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbGlicmFyeS5vcmciLCJhdWQiOiJodHRwOi8vbGlicmFyeS5jb20iLCJpYXQiOjE3MzE5ODE4MTAsImV4cCI6MTczMTk4NTQxMCwiZGF0YSI6eyJ1c2VyX2lkIjozMX19.2jv-Fm82EY2jaJ_nOuSfmdWvb3jmS2lp_9uJ0Vd9P6k",
  "data": null
}
```
**PUBLIC SHOW**

* method- GET

* end point- /user/register

 * Description- Retrieves a list of all registered users. The response includes user details such as username and password. This endpoint is typically accessible to administrators or users with appropriate permissions using token.

 **Example Requesst**

 GET /user/show

 ```
 {
  auth
  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbGlicmFyeS5vcmciLCJhdWQiOiJodHRwOi8vbGlicmFyeS5jb20iLCJpYXQiOjE3MzE5ODI0NjAsImV4cCI6MTczMTk4NjA2MCwiZGF0YSI6eyJ1c2VyX2lkIjozMX19.b05Wu3VHlfExbP1aywvex3NWf0YvG3m0KAptc0bFenM
}
```
**Response**

```
{
  "status": "success",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbGlicmFyeS5vcmciLCJhdWQiOiJodHRwOi8vbGlicmFyeS5jb20iLCJpYXQiOjE3MzE5ODI0ODAsImV4cCI6MTczMTk4NjA4MCwiZGF0YSI6eyJ1c2VyX2lkIjozMX19.OMcugOti2SsogC5i1V4TzPbX-znyIQsXEb8exVFHYiE",
  "data": [
    {
      "user_id": 6,
      "username": "mariane rivera"
    },
    {
      "user_id": 27,
      "username": "jowilldave"
    },
    {
      "user_id": 29,
      "username": "jowilldave"
    },
    {
      "user_id": 30,
      "username": "estaciodave"
    },
    {
      "user_id": 31,
      "username": "markemerson"
    }
  ]
}
```

**USER DELETE**

* method- DEL

* end point- /user/delete

 * Description- Enables an admin user to delete another user. The request must include a valid JWT token for authentication and authorization.


 **Example Requesst**

 DEL /user/delete

 ```
 {
  auth
  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbGlicmFyeS5vcmciLCJhdWQiOiJodHRwOi8vbGlicmFyeS5jb20iLCJpYXQiOjE3MzE5ODI2NzIsImV4cCI6MTczMTk4NjI3MiwiZGF0YSI6eyJ1c2VyX2lkIjozMX19.rPNyUcS60ssk9U-ZwN6K4vFe56a-oetinKHe2OxuE7U
}
```
**Response**

```
{
  "status": "success",
  "data": "User account deleted"
}
```