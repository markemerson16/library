<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';

session_start(); // Start session to keep track of used tokens

// Array to keep track of used tokens
if (!isset($_SESSION['used_tokens'])) {
$_SESSION['used_tokens'] = [];
}

$app = new \Slim\App;

// Middleware to validate JWT token and check if it's been used
$authMiddleware = function (Request $request, Response $response, callable $next) {
$authHeader = $request->getHeader('Authorization');

if ($authHeader) {
$token = str_replace('Bearer ', '', $authHeader[0]);

// Check if token has been used
if (in_array($token, $_SESSION['used_tokens'])) {
return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
}

try {
$decoded = JWT::decode($token, new Key('server_hack', 'HS256'));
$request = $request->withAttribute('decoded', $decoded);
} catch (\Exception $e) {
return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized: " . $e->getMessage()))));
}

// Revoke the token after using it
$_SESSION['used_tokens'][] = $token;
} else {
return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token not provided"))));
}

return $next($request, $response);
};

// User registration
$app->post('/user/register', function (Request $request, Response $response, array $args) {
$data = json_decode($request->getBody());

$usr = trim($data->username);
$pass = trim($data->password);

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Check if username already exists
$stmt = $conn->prepare("SELECT * FROM users_tbl WHERE username = :username");
$stmt->execute([':username' => $usr]);

if ($stmt->rowCount() > 0) {
$response->getBody()->write(json_encode(array("status" => "fail", "data" => "Username already exists")));
return $response;
}

$sql = "INSERT INTO users_tbl (username, password) VALUES (:username, :password)";
$stmt = $conn->prepare($sql);
$stmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

$response->getBody()->write(json_encode(array("status" => "success", "data" => null)));

} catch (PDOException $e) {
$response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
}
return $response;
});

// User authentication
$app->post('/user/auth', function (Request $request, Response $response, array $args) {
$data = json_decode($request->getBody());

if (!isset($data->username) || !isset($data->password)) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid input data"))));
}

$usr = trim($data->username);
$pass = trim($data->password);

$servername = "localhost";
$db_username = "root";
$db_password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$checkUserStmt = $conn->prepare("SELECT * FROM users_tbl WHERE username = :username");
$checkUserStmt->execute([':username' => $usr]);

if ($checkUserStmt->rowCount() == 0) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Incorrect username"))));
}

$checkPassStmt = $conn->prepare("SELECT * FROM users_tbl WHERE username = :username AND password = :password");
$checkPassStmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

if ($checkPassStmt->rowCount() == 0) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Incorrect password"))));
}

// If username and password are correct, generate the JWT token
$data = $checkPassStmt->fetch(PDO::FETCH_ASSOC);
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600, 
'data' => array("user_id" => $data['user_id'])
];
$jwt = JWT::encode($payload, $key, 'HS256');

return $response->getBody()->write(json_encode(array("status" => "success", "token" => $jwt, "data" => null)));

} catch (PDOException $e) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
}
});

// Updating user account 
$app->put('/user/update', function (Request $request, Response $response, array $args) {
// Parse input data
$data = json_decode($request->getBody());

// Validate required fields (new_username and new_password must be present)
if (empty($data->new_username) || empty($data->new_password)) {
return $response->withJson([
"status" => "fail",
"data" => "Invalid input data"
], 400);
}

// Database configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "library";

try {
// Establish database connection
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Retrieve user ID from decoded JWT token (prioritized)
$userId = $request->getAttribute('decoded')->data->user_id;

// Fetch the user by user_id to ensure they exist
$stmt = $conn->prepare("SELECT * FROM users_tbl WHERE user_id = :user_id");
$stmt->execute([':user_id' => $userId]);

// Return error if no matching user is found
if ($stmt->rowCount() === 0) {
return $response->withJson([
    "status" => "fail",
    "data" => "User not found"
], 404);
}

// Update the user's username and password
$updateStmt = $conn->prepare("UPDATE users_tbl SET username = :new_username, password = :new_password WHERE user_id = :userId");
$updateStmt->execute([
':new_username' => $data->new_username,
':new_password' => hash('SHA256', $data->new_password),
':userId' => $userId
]);

// Revoke the current token by adding it to the used tokens list
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new JWT token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600, // Token expires in 1 hour
'data' => ["user_id" => $userId]
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

// Return success response with new token
return $response->withJson([
"status" => "success",
"token" => $new_jwt,
"data" => null
]);

} catch (PDOException $e) {
// Return error response in case of exception
return $response->withJson([
"status" => "fail",
"data" => ["title" => $e->getMessage()]
], 500);
}
})->add($authMiddleware);


// Deleting user account 
$app->delete('/user/delete', function (Request $request, Response $response, array $args) {
// Database connection settings
$servername = "localhost";
$username = "root";          // Ensure this is correct
$password = "";              // Ensure this is correct (set your MySQL password if needed)
$dbname = "library";

try {
// Establish database connection
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Retrieve the user ID from the request payload or query parameters
$data = json_decode($request->getBody(), true);
$userId = $data['user_id'] ?? null;

// Validate if user_id is provided
if (!$userId) {
return $response->withJson([
    "status" => "fail",
    "data" => "User ID not provided"
], 400);
}

// Check if the user exists by user_id
$stmt = $conn->prepare("SELECT * FROM users_tbl WHERE user_id = :user_id");
$stmt->execute([':user_id' => $userId]);

// If the user is not found, return an error
if ($stmt->rowCount() === 0) {
return $response->withJson([
    "status" => "fail",
    "data" => "User with the given user_id not found"
], 404);
}

// Delete the user from the database based on user_id
$deleteStmt = $conn->prepare("DELETE FROM users_tbl WHERE user_id = :user_id");
$deleteStmt->execute([':user_id' => $userId]);

// Revoke the current token by adding it to the used tokens list
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Return success response
return $response->withJson([
"status" => "success",
"data" => "User account deleted"
], 200);

} catch (PDOException $e) {
// Return error response in case of exception
return $response->withJson([
"status" => "fail",
"data" => ["title" => $e->getMessage()]
], 500);
}
})->add($authMiddleware);


// Display users
$app->get('/user/show', function (Request $request, Response $response, array $args) {
// Decode the token to get the user_id
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

// Get query parameters
$queryParams = $request->getQueryParams();
$userId = $queryParams['user_id'] ?? null; 

// Database connection settings
$servername = "localhost";
$db_username = "root";  // Ensure this is correct
$password = "";          // Ensure this is correct (set your MySQL password if needed)
$dbname = "library";

try {
// Establish database connection
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// If user_id is provided, fetch the specific user
if ($userId) {
$stmt = $conn->prepare("SELECT user_id, username FROM users_tbl WHERE user_id = :user_id");
$stmt->execute([':user_id' => $userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user) {
    // Revoke the current token
    $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
    $_SESSION['used_tokens'][] = $token;

    // Generate a new token for rotation
    $key = 'server_hack'; // Secret key for signing the token
    $iat = time();
    $payload = [
        'iss' => 'http://library.org',
        'aud' => 'http://library.com',
        'iat' => $iat,
        'exp' => $iat + 3600, // Token expires in 1 hour
        'data' => array("user_id" => $tokenUserId)
    ];
    $new_jwt = JWT::encode($payload, $key, 'HS256');

    // Return success with the new token
    return $response->getBody()->write(json_encode(array(
        "status" => "success",
        "token" => $new_jwt,
        "data" => $user
    )));
} else {
    return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "User not found")));
}
} else {
// Fetch all users if user_id is not provided
$stmt = $conn->prepare("SELECT user_id, username FROM users_tbl");
$stmt->execute();
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

if (count($users) > 0) {
    // Revoke the current token and generate a new one
    $token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
    $_SESSION['used_tokens'][] = $token;

    $key = 'server_hack';
    $iat = time();
    $payload = [
        'iss' => 'http://library.org',
        'aud' => 'http://library.com',
        'iat' => $iat,
        'exp' => $iat + 3600,
        'data' => array("user_id" => $tokenUserId)
    ];
    $new_jwt = JWT::encode($payload, $key, 'HS256');

    return $response->getBody()->write(json_encode(array(
        "status" => "success",
        "token" => $new_jwt,
        "data" => $users
    )));
} else {
    return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No users found")));
}
}

} catch (PDOException $e) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
}
})->add($authMiddleware); // Ensure this route uses the authentication middleware


// Add author's name 
$app->post('/author/add', function (Request $request, Response $response, array $args) {
// Decode the JWT token to get user_id
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

// Parse the request body
$data = json_decode($request->getBody());

// Validate that name is provided
if (!isset($data->name) || empty($data->name)) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data")));
}

$name = trim($data->name);

// Database connection settings
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Check if the author's name already exists
$stmt = $conn->prepare("SELECT COUNT(*) FROM author WHERE name = :name");
$stmt->execute([':name' => $name]);
$count = $stmt->fetchColumn();

if ($count > 0) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author name already exists")));
}

// Insert the new author into the database
$stmt = $conn->prepare("INSERT INTO author (name) VALUES (:name)");
$stmt->execute([':name' => $name]);

// Token rotation
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => null)));

} catch (PDOException $e) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
}
})->add($authMiddleware); // Make sure the route uses the auth middleware


// Update author's name 
$app->put('/author/update', function (Request $request, Response $response, array $args) {
// Decode the JWT token to get user_id
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

// Decode request body as an associative array
$data = json_decode($request->getBody(), true);

// Check if 'author_id' and 'name' are present and not empty
if (!isset($data['author_id']) || !isset($data['name']) || empty($data['author_id']) || empty($data['name'])) {
return $response->getBody()->write(json_encode([
"status" => "fail", 
"data" => "'author_id' and 'name' must be provided"
]));
}

$author_id = intval($data['author_id']);
$newName = trim($data['name']);

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Check if the author exists by author_id
$stmt = $conn->prepare("SELECT COUNT(*) FROM author WHERE author_id = :author_id");
$stmt->execute([':author_id' => $author_id]);
$authorCount = $stmt->fetchColumn();

if ($authorCount == 0) {
return $response->getBody()->write(json_encode(["status" => "fail", "data" => "Author ID doesn't exist"]));
}

// Check if the new author's name already exists (excluding the current author)
$stmt = $conn->prepare("SELECT COUNT(*) FROM author WHERE name = :new_name AND author_id != :author_id");
$stmt->execute([':new_name' => $newName, ':author_id' => $author_id]);
$newNameCount = $stmt->fetchColumn();

if ($newNameCount > 0) {
return $response->getBody()->write(json_encode(["status" => "fail", "data" => "Author's new name already exists"]));
}

// Update the author's name
$stmt = $conn->prepare("UPDATE author SET name = :new_name WHERE author_id = :author_id");
$stmt->execute([':new_name' => $newName, ':author_id' => $author_id]);

// Token rotation
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->getBody()->write(json_encode(["status" => "success", "token" => $new_jwt, "data" => null]));

} catch (PDOException $e) {
return $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
}
})->add($authMiddleware);



// Delete author 
$app->delete('/author/delete', function (Request $request, Response $response, array $args) {
// Decode the JWT token to get user_id
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

$data = json_decode($request->getBody());

if (!isset($data->author_id) || empty($data->author_id)) {
return $response->withJson(["status" => "fail", "data" => "Invalid input data"]);
}

$authorId = intval($data->author_id);

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$stmt = $conn->prepare("SELECT COUNT(*) FROM author WHERE author_id = :author_id");
$stmt->execute([':author_id' => $authorId]);
$count = $stmt->fetchColumn();

if ($count == 0) {
return $response->withJson(["status" => "fail", "data" => "Author not found"]);
}

// Delete the author
$stmt = $conn->prepare("DELETE FROM author WHERE author_id = :author_id");
$stmt->execute([':author_id' => $authorId]);

// Token rotation
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->withJson(["status" => "success", "token" => $new_jwt, "data" => null]);

} catch (PDOException $e) {
return $response->withJson(["status" => "fail", "data" => ["title" => $e->getMessage()]]);
}
})->add($authMiddleware);


// Display authors' names
$app->get('/author/show', function (Request $request, Response $response, array $args) {
// Decode the JWT token to get user_id
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

$queryParams = $request->getQueryParams();
$name = $queryParams['name'] ?? null; 

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

if ($name) {
$stmt = $conn->prepare("SELECT * FROM author WHERE name = :name");
$stmt->execute([':name' => $name]);
$author = $stmt->fetch(PDO::FETCH_ASSOC);
} else {
$stmt = $conn->prepare("SELECT * FROM author");
$stmt->execute();
$authors = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Token rotation
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

if ($name && $author) {
return $response->withJson(["status" => "success", "token" => $new_jwt, "data" => $author]);
} elseif ($authors) {
return $response->withJson(["status" => "success", "token" => $new_jwt, "data" => $authors]);
} else {
return $response->withJson(["status" => "fail", "data" => "No authors found"]);
}
} catch (PDOException $e) {
return $response->withJson(["status" => "fail", "data" => ["title" => $e->getMessage()]]);
}
})->add($authMiddleware);


//Add book
$app->post('/book/add', function (Request $request, Response $response, array $args) {
// Parse request body
$data = json_decode($request->getBody());

// Validate input: both title and author_id must be provided and non-empty
if (!isset($data->title) || !isset($data->author_id) || empty($data->title) || empty($data->author_id)) {
return $response->withStatus(400)
            ->getBody()
            ->write(json_encode([
                "status" => "fail",
                "data" => "Invalid input data. Both 'title' and 'author_id' must be provided."
            ]));
}

// Clean and assign inputs
$title = trim($data->title);
$author_id = intval($data->author_id);

// Database connection settings
$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
// Establish the database connection
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Retrieve userId from JWT token
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

// Check if the author exists in the database
$authorStmt = $conn->prepare("SELECT COUNT(*) FROM author WHERE author_id = :author_id");
$authorStmt->execute([':author_id' => $author_id]);
$authorCount = $authorStmt->fetchColumn();

if ($authorCount == 0) {
return $response->withStatus(404)
                ->getBody()
                ->write(json_encode([
                    "status" => "fail",
                    "data" => "Author ID not found"
                ]));
}

// Check if a book with the same title already exists
$bookStmt = $conn->prepare("SELECT COUNT(*) FROM book WHERE title = :title");
$bookStmt->execute([':title' => $title]);
$bookCount = $bookStmt->fetchColumn();

if ($bookCount > 0) {
return $response->withStatus(409)
                ->getBody()
                ->write(json_encode([
                    "status" => "fail",
                    "data" => "Book with this title already exists"
                ]));
}

// Insert the new book into the database
$stmt = $conn->prepare("INSERT INTO book (title, author_id) VALUES (:title, :author_id)");
$stmt->execute([':title' => $title, ':author_id' => $author_id]);

// Token rotation logic
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new JWT token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600, // Token expiry set to 1 hour
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

// Return success response with new token
return $response->withStatus(201)
            ->getBody()
            ->write(json_encode([
                "status" => "success",
                "data" => "Book added successfully",
                "token" => $new_jwt
            ]));

} catch (PDOException $e) {
return $response->withStatus(500)
            ->getBody()
            ->write(json_encode([
                "status" => "fail",
                "data" => array("error" => $e->getMessage())
            ]));
}
})->add($authMiddleware);


// Update book
$app->put('/book/update', function (Request $request, Response $response, array $args) {
$data = json_decode($request->getBody());

if (!isset($data->old_title) || !isset($data->new_title)) {
return $response->withStatus(400)->getBody()->write(json_encode(array(
"status" => "fail",
"data" => "Invalid input data. Both 'old_title' and 'new_title' must be provided."
)));
}

$oldTitle = trim($data->old_title);
$newTitle = trim($data->new_title);

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Decode token to get userId from JWT token (for token rotation)
$tokenUser_id = $request->getAttribute('decoded')->data->user_id;

// Check if the old title exists in the 'book' table
$oldStmt = $conn->prepare("SELECT COUNT(*) FROM book WHERE title = :old_title");
$oldStmt->execute([':old_title' => $oldTitle]);
$oldCount = $oldStmt->fetchColumn();

if ($oldCount == 0) {
return $response->withStatus(404)->getBody()->write(json_encode(array(
    "status" => "fail",
    "data" => "Old book title does not exist."
)));
}

// Check if the new title already exists in the 'book' table
$newStmt = $conn->prepare("SELECT COUNT(*) FROM book WHERE title = :new_title");
$newStmt->execute([':new_title' => $newTitle]);
$newCount = $newStmt->fetchColumn();

if ($newCount > 0) {
return $response->withStatus(409)->getBody()->write(json_encode(array(
    "status" => "fail",
    "data" => "New book title already exists."
)));
}

// Update the title in the 'book' table
$stmt = $conn->prepare("UPDATE book SET title = :new_title WHERE title = :old_title");
$stmt->execute([
':new_title' => $newTitle,
':old_title' => $oldTitle
]);

// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("userId" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->getBody()->write(json_encode(array(
"status" => "success",
"data" => "Book title updated successfully",
"token" => $new_jwt
)));

} catch (PDOException $e) {
return $response->getBody()->write(json_encode(array(
"status" => "fail",
"data" => array("error" => $e->getMessage())
)));
}
})->add($authMiddleware);

// Delete book by title
$app->delete('/book/delete', function (Request $request, Response $response, array $args) {
$data = json_decode($request->getBody());

if (!isset($data->title) || empty($data->title)) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data")));
}

$title = trim($data->title);

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Decode token to get userId from JWT token (for token rotation)
$tokenUserId = $request->getAttribute('decoded')->data->user_id;


// Check if the book exists in the 'book' table
$stmt = $conn->prepare("SELECT COUNT(*) FROM book WHERE title = :title");
$stmt->execute([':title' => $title]);
$count = $stmt->fetchColumn();

if ($count == 0) {
return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book not found")));
}

// Delete the book from the 'book' table
$stmt = $conn->prepare("DELETE FROM book WHERE title = :title");
$stmt->execute([':title' => $title]);

// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("userId" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->getBody()->write(json_encode(array(
"status" => "success",
"data" => "Book deleted successfully",
"token" => $new_jwt
)));

} catch (PDOException $e) {
return $response->getBody()->write(json_encode(array(
"status" => "fail",
"data" => array("error" => $e->getMessage())
)));
}
})->add($authMiddleware);



// ADd book_author
$app->post('/books_authors/add', function (Request $request, Response $response, array $args) {
$data = json_decode($request->getBody());

if (!isset($data->book_id) || !isset($data->author_id)) {
return $response->withStatus(400)->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data. Both 'bookId' and 'authorId' must be provided.")));
}

$book_id = $data->book_id;
$author_id = $data->author_id;

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Decode token to get userId from JWT token (for token rotation)
$tokenUser_id = $request->getAttribute('decoded')->data->user_id;

$bookStmt = $conn->prepare("SELECT COUNT(*) FROM book WHERE book_id = :book_id");
$bookStmt->execute([':book_id' => $book_id]);
$bookCount = $bookStmt->fetchColumn();

if ($bookCount == 0) {
return $response->withStatus(404)->getBody()->write(json_encode(array("status" => "fail", "data" => "Book ID not found")));
}

$authorStmt = $conn->prepare("SELECT COUNT(*) FROM author WHERE author_id = :author_id");
$authorStmt->execute([':author_id' => $author_id]);
$authorCount = $authorStmt->fetchColumn();

if ($authorCount == 0) {
return $response->withStatus(404)->getBody()->write(json_encode(array("status" => "fail", "data" => "Author ID not found")));
}

$checkStmt = $conn->prepare("SELECT COUNT(*) FROM book_author WHERE book_id = :book_id AND author_id = :author_id");
$checkStmt->execute([':book_id' => $book_id, ':author_id' => $author_id]);
$existingCount = $checkStmt->fetchColumn();

if ($existingCount > 0) {
return $response->withStatus(409)->getBody()->write(json_encode(array("status" => "fail", "data" => "This book-author combination already exists.")));
}

$stmt = $conn->prepare("INSERT INTO book_author (book_id, author_id) VALUES (:book_id, :author_id)");
$stmt->execute([':book_id' => $book_id, ':author_id' => $author_id]);

// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600, 
'data' => array("user_id" => $tokenUser_id)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->withStatus(201)->getBody()->write(json_encode(array(
"status" => "success",
"token" => $new_jwt,
"data" => null
)));

} catch (PDOException $e) {
return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
}
})->add($authMiddleware);

//Update book_author
$app->put('/books_authors/update', function (Request $request, Response $response, array $args) {
$data = json_decode($request->getBody());

if (!isset($data->collectionId) || (!isset($data->new_bookId) && !isset($data->new_authorId))) {
return $response->withStatus(400)->getBody()->write(json_encode(array(
"status" => "fail",
"data" => "Invalid input data. 'collectionId' must be provided, and at least one of 'new_bookId' or 'new_authorId' must be provided."
)));
}

$collectionId = $data->collectionId;
$new_bookId = $data->new_bookId ?? null;
$new_authorId = $data->new_authorId ?? null;

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Decode token to get userId from JWT token (for token rotation)
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

$stmt = $conn->prepare("SELECT * FROM book_author WHERE collection_id = :collection_id");
$stmt->execute([':collection_id' => $collectionId]);
$record = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$record) {
return $response->withStatus(404)->getBody()->write(json_encode(array("status" => "fail", "data" => "Record not found")));
}

$current_bookId = $record['book_id'];
$current_authorId = $record['author_id'];

$updated_bookId = $new_bookId ? $new_bookId : $current_bookId;
$updated_authorId = $new_authorId ? $new_authorId : $current_authorId;

$checkStmt = $conn->prepare("SELECT COUNT(*) FROM book_author WHERE book_id = :book_id AND author_id = :author_id AND collection_id != :collection_id");
$checkStmt->execute([
':book_id' => $updated_bookId,
':author_id' => $updated_authorId,
':collection_id' => $collectionId
]);
$existingCount = $checkStmt->fetchColumn();

if ($existingCount > 0) {
return $response->withStatus(409)->getBody()->write(json_encode(array("status" => "fail", "data" => "This book-author combination already exists.")));
}

$updateStmt = $conn->prepare("UPDATE book_author SET book_id = :book_id, author_id = :author_id WHERE collection_id = :collection_id");
$updateStmt->execute([
':book_id' => $updated_bookId,
':author_id' => $updated_authorId,
':collection_id' => $collectionId
]);

// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->withStatus(200)->getBody()->write(json_encode(array(
"status" => "success",
"token" => $new_jwt,
"data" => null
)));

} catch (PDOException $e) {
return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
}
})->add($authMiddleware);

/// Delete book_author
$app->delete('/books_authors/delete', function (Request $request, Response $response, array $args) {
$data = json_decode($request->getBody());

// Check if collection_id is provided
if (!isset($data->collection_id)) {
return $response->withStatus(400)->getBody()->write(json_encode(array(
"status" => "fail",
"data" => "Invalid input data. 'collection_id' must be provided." // Ensure the message matches the property name
)));
}

$collectionId = $data->collection_id; // Use collection_id

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Decode token to get userId from JWT token (for token rotation)
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

// Check if record exists
$stmt = $conn->prepare("SELECT COUNT(*) FROM book_author WHERE collection_id = :collection_id");
$stmt->execute([':collection_id' => $collectionId]);
$count = $stmt->fetchColumn();

if ($count == 0) {
return $response->withStatus(404)->getBody()->write(json_encode(array(
    "status" => "fail",
    "data" => "Record not found."
)));
}

// Delete the record
$stmt = $conn->prepare("DELETE FROM book_author WHERE collection_id = :collection_id");
$stmt->execute([':collection_id' => $collectionId]);

// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600,
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->withStatus(200)->getBody()->write(json_encode(array(
"status" => "success",
"token" => $new_jwt,
"data" => null
)));

} catch (PDOException $e) {
return $response->withStatus(500)->getBody()->write(json_encode(array(
"status" => "fail",
"data" => array("title" => $e->getMessage())
)));
}
})->add($authMiddleware);


//show books_authors
$app->get('/books_authors/show', function (Request $request, Response $response, array $args) {
$queryParams = $request->getQueryParams();
$bookTitle = $queryParams['bookTitle'] ?? null; 
$authorName = $queryParams['authorName'] ?? null; 

$servername = "localhost";
$db_username = "root";
$password = "";
$dbname = "library";

try {
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Decode token to get userId from JWT token (for token rotation)
$tokenUserId = $request->getAttribute('decoded')->data->user_id;

if ($bookTitle) {
$stmt = $conn->prepare("SELECT ba.collection_id, b.title AS bookTitle, a.name AS authorName
                FROM book_author ba
                JOIN book b ON ba.book_id = b.book-id
                JOIN author a ON ba.author_id = a.author-id
                WHERE b.title = :bookTitle");
$stmt->execute([':bookTitle' => $bookTitle]);
$relationship = $stmt->fetch(PDO::FETCH_ASSOC);

if ($relationship) {
// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600, 
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->withStatus(200)->getBody()->write(json_encode(array(
"status" => "success",
"data" => $relationship,
"token" => $new_jwt
)));
} else {
return $response->withStatus(404)->getBody()->write(json_encode(array(
"status" => "fail",
"data" => "No relationship found for the given book title"
)));
}
} elseif ($authorName) {
$stmt = $conn->prepare("SELECT ba.collection-id, b.title AS bookTitle, a.name AS authorName
                FROM book_author ba
                JOIN book b ON ba.book_id = b.book_id
                JOIN author a ON ba.author_id = a.author_id
                WHERE a.name = :authorName");
$stmt->execute([':authorName' => $authorName]);
$relationship = $stmt->fetch(PDO::FETCH_ASSOC);

if ($relationship) {
// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600, 
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->withStatus(200)->getBody()->write(json_encode(array(
"status" => "success",
"data" => $relationship,
"token" => $new_jwt
)));
} else {
return $response->withStatus(404)->getBody()->write(json_encode(array(
"status" => "fail",
"data" => "No relationship found for the given author name"
)));
}
} else {
$stmt = $conn->prepare("SELECT ba.collection_id, b.title AS bookTitle, a.name AS authorName
                FROM book_author ba
                JOIN book b ON ba.book_id = b.book_id
                JOIN author a ON ba.author_id = a.author_id");
$stmt->execute();
$relationships = $stmt->fetchAll(PDO::FETCH_ASSOC);

if (count($relationships) > 0) {
// Revoke the current token
$token = str_replace('Bearer ', '', $request->getHeader('Authorization')[0]);
$_SESSION['used_tokens'][] = $token;

// Generate a new token
$key = 'server_hack';
$iat = time();
$payload = [
'iss' => 'http://library.org',
'aud' => 'http://library.com',
'iat' => $iat,
'exp' => $iat + 3600, // Token valid for 1 hour
'data' => array("user_id" => $tokenUserId)
];
$new_jwt = JWT::encode($payload, $key, 'HS256');

return $response->withStatus(200)->getBody()->write(json_encode(array(
"status" => "success",
"token" => $new_jwt,
"data" => $relationships
)));
} else {
return $response->withStatus(404)->getBody()->write(json_encode(array(
"status" => "fail",
"data" => "No books-authors relationships found"
)));
}
}

} catch (PDOException $e) {
return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
}
})->add($authMiddleware);

$app->run();
?>