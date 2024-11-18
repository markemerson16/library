<!-- <?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

    require '../src/vendor/autoload.php';

    $app = new \Slim\App;

    // Middleware to validate JWT token
    $authMiddleware = function (Request $request, Response $response, callable $next) {
        $authHeader = $request->getHeader('Authorization');

        if ($authHeader) {
            $token = str_replace('Bearer ', '', $authHeader[0]);
            try {
                $decoded = JWT::decode($token, new Key('server_hack', 'HS256'));
                // Store the decoded token in the request attributes if needed
                $request = $request->withAttribute('decoded', $decoded);
            } catch (\Exception $e) {
                return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized: " . $e->getMessage()))));
            }
        } else {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token not provided"))));
        }

        return $next($request, $response);
    };

    // User registration
    // $app->post('/user/register', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());
    //     $usr = $data->username;
    //     $pass = $data->password;

    //     $servername = "localhost";
    //     $username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         // Check if username already exists
    //         $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
    //         $stmt->execute([':username' => $usr]);

    //         if ($stmt->rowCount() > 0) {
    //             $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Username already exists")));
    //             return $response;
    //         }

    //         $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
    //         $stmt = $conn->prepare($sql);
    //         $stmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

    //         $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));

    //     } catch (PDOException $e) {
    //         $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    //     return $response;
    // });

    // // User authentication (acts as log-in too)
    // $app->post('/user/authenticate', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());

    //     if (!isset($data->username) || !isset($data->password)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid input data"))));
    //     }

    //     $usr = $data->username;
    //     $pass = $data->password;

    //     $servername = "localhost";
    //     $username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         $sql = "SELECT * FROM users WHERE username = :username AND password = :password";
    //         $stmt = $conn->prepare($sql);
    //         $stmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);
    //         $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

    //         if (count($data) == 1) {
    //             $key = 'server_hack';
    //             $iat = time();
    //             $payload = [
    //                 'iss' => 'http://library.org',
    //                 'aud' => 'http://library.com',
    //                 'iat' => $iat,
    //                 'exp' => $iat + 3600, // Token valid for 1 hour
    //                 'data' => array("userId" => $data[0]['userId'])
    //             ];
    //             $jwt = JWT::encode($payload, $key, 'HS256');
    //             $response->getBody()->write(json_encode(array("status" => "success", "token" => $jwt, "data" => null)));
    //         } else {
    //             $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Authentication Failed!"))));
    //         }

    //     } catch (PDOException $e) {
    //         $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    //     return $response;
    // });

    // // Updating user account (requires token)
    // $app->put('/user/update', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());

    //     if (!isset($data->username) || !isset($data->password) || !isset($data->new_username)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data")));
    //     }

    //     $usr = $data->username; 
    //     $new_usr = $data->new_username; 
    //     $pass = $data->password;

    //     $userId = $request->getAttribute('userId'); 

    //     $servername = "localhost";
    //     $username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         // Check if the current username exists
    //         $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
    //         $stmt->execute([':username' => $usr]);

    //         if ($stmt->rowCount() === 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Current username not found")));
    //         }

    //         // Check if the new username already exists
    //         $stmt = $conn->prepare("SELECT * FROM users WHERE username = :new_username");
    //         $stmt->execute([':new_username' => $new_usr]);

    //         if ($stmt->rowCount() > 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "New username already exists")));
    //         }

    //         // Updating the user's username and password
    //         $stmt = $conn->prepare("UPDATE users SET username = :new_username, password = :password WHERE username = :username");
    //         $stmt->execute([
    //             ':new_username' => $new_usr,
    //             ':password' => hash('SHA256', $pass),
    //             ':username' => $usr
    //         ]);

    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null))); 

    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // });

    // // Delete user (requires token)
    // $app->delete('/user/delete', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());

    //     $username = $data->username; 

    //     if (!isset($username)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Username not provided")));
    //     }

    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         // Check if the username exists
    //         $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
    //         $stmt->execute([':username' => $username]);

    //         if ($stmt->rowCount() === 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Username not found")));
    //         }

    //         // Delete user from the database
    //         $stmt = $conn->prepare("DELETE FROM users WHERE username = :username");
    //         $stmt->execute([':username' => $username]);

    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => "User deleted successfully")));

    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware); 

    // // Display users (requires token)
    // $app->get('/user/display', function (Request $request, Response $response, array $args) {
    //     $queryParams = $request->getQueryParams();
    //     $userId = $queryParams['userId'] ?? null; // Get userId from query params if provided

    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         // If a userId is provided, fetch that specific user
    //         if ($userId) {
    //             $stmt = $conn->prepare("SELECT userId, username FROM users WHERE userId = :userId");
    //             $stmt->execute([':userId' => $userId]);
    //             $user = $stmt->fetch(PDO::FETCH_ASSOC);

    //             if ($user) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $user)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "User not found")));
    //             }
    //         } else {
    //             // Fetch all users if no userId is provided
    //             $stmt = $conn->prepare("SELECT userId, username FROM users");
    //             $stmt->execute();
    //             $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    //             if (count($users) > 0) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $users)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No users found")));
    //             }
    //         }

    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware); 

    // // Add author's name
    // $app->post('/author/add', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());
    
    //     // Check if the 'name' field is set and not empty
    //     if (!isset($data->name) || empty($data->name)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data")));
    //     }
    
    //     $name = trim($data->name);
    
    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    //         // Check if the name already exists
    //         $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :name");
    //         $stmt->execute([':name' => $name]);
    //         $count = $stmt->fetchColumn();
    
    //         if ($count > 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author's name already exists")));
    //         }
    
    //         // Insert new author into the database
    //         $stmt = $conn->prepare("INSERT INTO authors (name) VALUES (:name)");
    //         $stmt->execute([':name' => $name]);
    
    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    
    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware); 
    
    // // Update author's name
    // $app->put('/author/update', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());
    
    //     if (!isset($data->old_name) || !isset($data->new_name) || empty($data->old_name) || empty($data->new_name)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Both 'old_name' and 'new_name' must be provided")));
    //     }
    
    //     $oldName = trim($data->old_name);
    //     $newName = trim($data->new_name);
    
    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :old_name");
    //         $stmt->execute([':old_name' => $oldName]);
    //         $oldCount = $stmt->fetchColumn();
    
    //         if ($oldCount == 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Old author's name does not exist")));
    //         }

    //         $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :new_name");
    //         $stmt->execute([':new_name' => $newName]);
    //         $newCount = $stmt->fetchColumn();
    
    //         if ($newCount > 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author's new name already exists")));
    //         }
    
    //         $stmt = $conn->prepare("UPDATE authors SET name = :new_name WHERE name = :old_name");
    //         $stmt->execute([':new_name' => $newName, ':old_name' => $oldName]);
    
    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    
    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);

    // // Delete author's name
    // $app->delete('/author/delete', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());
    
    //     // Check if the 'name' field is set and not empty
    //     if (!isset($data->name) || empty($data->name)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data")));
    //     }
    
    //     $name = trim($data->name);
    
    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    //         // Check if the author exists in the database
    //         $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :name");
    //         $stmt->execute([':name' => $name]);
    //         $count = $stmt->fetchColumn();
    
    //         if ($count == 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author not found")));
    //         }
    
    //         // Delete the author from the database
    //         $stmt = $conn->prepare("DELETE FROM authors WHERE name = :name");
    //         $stmt->execute([':name' => $name]);
    
    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    
    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);  
    
    // //Display author's name
    // $app->get('/author/display', function (Request $request, Response $response, array $args) {
    //     $queryParams = $request->getQueryParams();
    //     $name = $queryParams['name'] ?? null; // Get author name from query params if provided
    
    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    //         if ($name) {
    //             // Fetch a specific author by name
    //             $stmt = $conn->prepare("SELECT * FROM authors WHERE name = :name");
    //             $stmt->execute([':name' => $name]);
    //             $author = $stmt->fetch(PDO::FETCH_ASSOC);
    
    //             if ($author) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $author)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author not found")));
    //             }
    //         } else {
    //             // Fetch all authors
    //             $stmt = $conn->prepare("SELECT * FROM authors");
    //             $stmt->execute();
    //             $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    //             if (count($authors) > 0) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $authors)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No authors found")));
    //             }
    //         }
    
    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);  
    
    // //Add book
    // $app->post('/book/add', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());
    
    //     // Validate that both title and authorId are provided
    //     if (!isset($data->title) || !isset($data->authorId) || empty($data->title) || empty($data->authorId)) {
    //         return $response->withStatus(400)->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data. Both 'title' and 'authorId' must be provided.")));
    //     }
    
    //     $title = trim($data->title);
    //     $authorId = intval($data->authorId);
    
    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    //         // Check if the provided authorId exists in the authors table
    //         $authorStmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorId = :authorId");
    //         $authorStmt->execute([':authorId' => $authorId]);
    //         $authorCount = $authorStmt->fetchColumn();
    
    //         if ($authorCount == 0) {
    //             return $response->withStatus(404)->getBody()->write(json_encode(array("status" => "fail", "data" => "Author ID not found")));
    //         }
    
    //         // Check if the provided book title already exists in the books table
    //         $bookStmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :title");
    //         $bookStmt->execute([':title' => $title]);
    //         $bookCount = $bookStmt->fetchColumn();
    
    //         if ($bookCount > 0) {
    //             return $response->withStatus(409)->getBody()->write(json_encode(array("status" => "fail", "data" => "Book with this title already exists")));
    //         }
    
    //         // Insert the new book into the books table
    //         $stmt = $conn->prepare("INSERT INTO books (title, authorId) VALUES (:title, :authorId)");
    //         $stmt->execute([':title' => $title, ':authorId' => $authorId]);
    
    //         // Return a success message
    //         return $response->withStatus(201)->getBody()->write(json_encode(array("status" => "success", "data" => "Book added successfully")));
    
    //     } catch (PDOException $e) {
    //         // Return failure response with error message
    //         return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "data" => array("error" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware); 
    
    // // Update book
    // $app->put('/book/update', function (Request $request, Response $response, array $args) {
    //     // Get the JSON data from the request
    //     $data = json_decode($request->getBody());
    
    //     // Validate input
    //     if (!isset($data->old_title) || !isset($data->new_title)) {
    //         return $response->withStatus(400)->getBody()->write(json_encode(array(
    //             "status" => "fail",
    //             "data" => "Invalid input data. Both 'old_title' and 'new_title' must be provided."
    //         )));
    //     }
    
    //     $oldTitle = trim($data->old_title);
    //     $newTitle = trim($data->new_title);
    
    //     // Database connection details
    //     $servername = "localhost";
    //     $username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         // Create a new PDO instance
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    //         // Check if the old title exists
    //         $oldStmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :old_title");
    //         $oldStmt->execute([':old_title' => $oldTitle]);
    //         $oldCount = $oldStmt->fetchColumn();
    
    //         if ($oldCount == 0) {
    //             return $response->withStatus(404)->getBody()->write(json_encode(array(
    //                 "status" => "fail",
    //                 "data" => "Old book title does not exist."
    //             )));
    //         }
    
    //         // Update the book title
    //         $stmt = $conn->prepare("UPDATE books SET title = :new_title WHERE title = :old_title");
    //         $stmt->execute([
    //             ':new_title' => $newTitle,
    //             ':old_title' => $oldTitle
    //         ]);
    
    //         // Return a success message
    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    
    //     } catch (PDOException $e) {
    //         // Return failure response with error message
    //         return $response->getBody()->write(json_encode(array(
    //             "status" => "fail",
    //             "data" => array("error" => $e->getMessage())
    //         )));
    //     }
    // });

    // // Delete book by title
    // $app->delete('/book/delete', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());

    //     // Check if the 'title' field is set and not empty
    //     if (!isset($data->title) || empty($data->title)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data")));
    //     }

    //     $title = trim($data->title);

    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         // Check if the book exists in the database
    //         $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :title");
    //         $stmt->execute([':title' => $title]);
    //         $count = $stmt->fetchColumn();

    //         if ($count == 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book not found")));
    //         }

    //         // Delete the book from the database
    //         $stmt = $conn->prepare("DELETE FROM books WHERE title = :title");
    //         $stmt->execute([':title' => $title]);

    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));

    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);

    // // Display books
    // $app->get('/book/display', function (Request $request, Response $response, array $args) {
    //     $queryParams = $request->getQueryParams();
    //     $title = $queryParams['title'] ?? null; // Get book title from query params if provided

    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         if ($title) {
    //             // Fetch a specific book by title
    //             $stmt = $conn->prepare("SELECT books.bookId, books.title, authors.name AS author 
    //                                     FROM books 
    //                                     JOIN authors ON books.authorId = authors.authorId 
    //                                     WHERE books.title = :title");
    //             $stmt->execute([':title' => $title]);
    //             $book = $stmt->fetch(PDO::FETCH_ASSOC);

    //             if ($book) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $book)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book not found")));
    //             }
    //         } else {
    //             // Fetch all books
    //             $stmt = $conn->prepare("SELECT books.bookId, books.title, authors.name AS author 
    //                                     FROM books 
    //                                     JOIN authors ON books.authorId = authors.authorId");
    //             $stmt->execute();
    //             $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

    //             if (count($books) > 0) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $books)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No books found")));
    //             }
    //         }

    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);

    // // ADd book_author
    // $app->post('/books_authors/add', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());
    
    //     // Check if 'bookId' and 'authorId' are provided in the payload
    //     if (!isset($data->bookId) || !isset($data->authorId)) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid input data. Both 'bookId' and 'authorId' must be provided.")));
    //     }
    
    //     $bookId = $data->bookId;
    //     $authorId = $data->authorId;
    
    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    //         // Check if the bookId exists in the books table
    //         $bookStmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookId = :bookId");
    //         $bookStmt->execute([':bookId' => $bookId]);
    //         $bookCount = $bookStmt->fetchColumn();
    
    //         if ($bookCount == 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book ID not found")));
    //         }
    
    //         // Check if the authorId exists in the authors table
    //         $authorStmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorId = :authorId");
    //         $authorStmt->execute([':authorId' => $authorId]);
    //         $authorCount = $authorStmt->fetchColumn();
    
    //         if ($authorCount == 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author ID not found")));
    //         }
    
    //         // Check if this bookId-authorId combination already exists
    //         $checkStmt = $conn->prepare("SELECT COUNT(*) FROM books_authors WHERE bookId = :bookId AND authorId = :authorId");
    //         $checkStmt->execute([':bookId' => $bookId, ':authorId' => $authorId]);
    //         $existingCount = $checkStmt->fetchColumn();
    
    //         if ($existingCount > 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "This book-author combination already exists.")));
    //         }
    
    //         // Insert into the books_authors table
    //         $stmt = $conn->prepare("INSERT INTO books_authors (bookId, authorId) VALUES (:bookId, :authorId)");
    //         $stmt->execute([':bookId' => $bookId, ':authorId' => $authorId]);
    
    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    
    //     } catch (PDOException $e) {
    //         // Return failure response with error message
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);

    // //Update book_author
    // $app->put('/books_authors/update', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());
    
    //     // Validate that collectionId is provided, and at least one of new_bookId or new_authorId is provided
    //     if (!isset($data->collectionId) || (!isset($data->new_bookId) && !isset($data->new_authorId))) {
    //         return $response->getBody()->write(json_encode(array(
    //             "status" => "fail",
    //             "data" => "Invalid input data. 'collectionId' must be provided, and at least one of 'new_bookId' or 'new_authorId' must be provided."
    //         )));
    //     }
    
    //     $collectionId = $data->collectionId;
    //     $new_bookId = $data->new_bookId ?? null;
    //     $new_authorId = $data->new_authorId ?? null;
    
    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";
    
    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    //         // Fetch the current record
    //         $stmt = $conn->prepare("SELECT * FROM books_authors WHERE collectionId = :collectionId");
    //         $stmt->execute([':collectionId' => $collectionId]);
    //         $record = $stmt->fetch(PDO::FETCH_ASSOC);
    
    //         if (!$record) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Record not found")));
    //         }
    
    //         $current_bookId = $record['bookId'];
    //         $current_authorId = $record['authorId'];
    
    //         // Use current values if new values are not provided
    //         $updated_bookId = $new_bookId ? $new_bookId : $current_bookId;
    //         $updated_authorId = $new_authorId ? $new_authorId : $current_authorId;
    
    //         // Check if the new combination of bookId and authorId already exists in the table
    //         $checkStmt = $conn->prepare("SELECT COUNT(*) FROM books_authors WHERE bookId = :bookId AND authorId = :authorId AND collectionId != :collectionId");
    //         $checkStmt->execute([
    //             ':bookId' => $updated_bookId,
    //             ':authorId' => $updated_authorId,
    //             ':collectionId' => $collectionId
    //         ]);
    //         $existingCount = $checkStmt->fetchColumn();
    
    //         if ($existingCount > 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "This book-author combination already exists.")));
    //         }
    
    //         // Update the record
    //         $updateStmt = $conn->prepare("UPDATE books_authors SET bookId = :bookId, authorId = :authorId WHERE collectionId = :collectionId");
    //         $updateStmt->execute([
    //             ':bookId' => $updated_bookId,
    //             ':authorId' => $updated_authorId,
    //             ':collectionId' => $collectionId
    //         ]);
    
    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
    
    //     } catch (PDOException $e) {
    //         // Return failure response with error message
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);
    
    // //delete book_author
    // $app->delete('/books_authors/delete', function (Request $request, Response $response, array $args) {
    //     $data = json_decode($request->getBody());

    //     // Check if bookId and authorId are provided
    //     if (!isset($data->bookId) || !isset($data->authorId)) {
    //         return $response->getBody()->write(json_encode(array(
    //             "status" => "fail",
    //             "data" => "Invalid input data. 'bookId' and 'authorId' must be provided."
    //         )));
    //     }

    //     $bookId = $data->bookId;
    //     $authorId = $data->authorId;

    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         // Check if the record exists in the books_authors table
    //         $stmt = $conn->prepare("SELECT COUNT(*) FROM books_authors WHERE bookId = :bookId AND authorId = :authorId");
    //         $stmt->execute([':bookId' => $bookId, ':authorId' => $authorId]);
    //         $count = $stmt->fetchColumn();

    //         if ($count == 0) {
    //             return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book-author combination not found.")));
    //         }

    //         // Delete the book-author relationship
    //         $stmt = $conn->prepare("DELETE FROM books_authors WHERE bookId = :bookId AND authorId = :authorId");
    //         $stmt->execute([':bookId' => $bookId, ':authorId' => $authorId]);

    //         return $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));

    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);

    // //display books_authors
    // $app->get('/books_authors/display', function (Request $request, Response $response, array $args) {
    //     $queryParams = $request->getQueryParams();
    //     $bookTitle = $queryParams['bookTitle'] ?? null; // Get book title from query params if provided
    //     $authorName = $queryParams['authorName'] ?? null; // Get author name from query params if provided

    //     $servername = "localhost";
    //     $db_username = "root";
    //     $password = "";
    //     $dbname = "library";

    //     try {
    //         $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $password);
    //         $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    //         if ($bookTitle) {
    //             // Fetch relationships by book title
    //             $stmt = $conn->prepare("SELECT ba.collectionId, b.title AS bookTitle, a.name AS authorName
    //                                     FROM books_authors ba
    //                                     JOIN books b ON ba.bookId = b.bookId
    //                                     JOIN authors a ON ba.authorId = a.authorId
    //                                     WHERE b.title = :bookTitle");
    //             $stmt->execute([':bookTitle' => $bookTitle]);
    //             $relationship = $stmt->fetch(PDO::FETCH_ASSOC);

    //             if ($relationship) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $relationship)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No relationship found for the given book title")));
    //             }
    //         } elseif ($authorName) {
    //             // Fetch relationships by author name
    //             $stmt = $conn->prepare("SELECT ba.collectionId, b.title AS bookTitle, a.name AS authorName
    //                                     FROM books_authors ba
    //                                     JOIN books b ON ba.bookId = b.bookId
    //                                     JOIN authors a ON ba.authorId = a.authorId
    //                                     WHERE a.name = :authorName");
    //             $stmt->execute([':authorName' => $authorName]);
    //             $relationship = $stmt->fetch(PDO::FETCH_ASSOC);

    //             if ($relationship) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $relationship)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No relationship found for the given author name")));
    //             }
    //         } else {
    //             // Fetch all books-authors relationships
    //             $stmt = $conn->prepare("SELECT ba.collectionId, b.title AS bookTitle, a.name AS authorName
    //                                     FROM books_authors ba
    //                                     JOIN books b ON ba.bookId = b.bookId
    //                                     JOIN authors a ON ba.authorId = a.authorId");
    //             $stmt->execute();
    //             $relationships = $stmt->fetchAll(PDO::FETCH_ASSOC);

    //             if (count($relationships) > 0) {
    //                 return $response->getBody()->write(json_encode(array("status" => "success", "data" => $relationships)));
    //             } else {
    //                 return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No books-authors relationships found")));
    //             }
    //         }

    //     } catch (PDOException $e) {
    //         return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    //     }
    // })->add($authMiddleware);


    


$app->run();
?> -->
