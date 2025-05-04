<?php
header("Access-Control-Allow-Origin: *"); // Allow any origin
header("Access-Control-Allow-Methods: GET, POST, OPTIONS"); // Allowed HTTP methods
header("Access-Control-Allow-Headers: Content-Type, Authorization"); // Allowed headers
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight (OPTIONS) requests automatically
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

class ApiHandler {
    private $endpoint;
    private $pdo; // PDO instance (placeholder for future database connection)

    /**
     * Constructor: Assigns the API endpoint and initializes the PDO connection.
     *
     * @param string $endpoint Extracted API endpoint from the URL.
     */
    public function __construct($endpoint) {
        $this->endpoint = $endpoint;
        // Comment out database initialization for now since we're using test data
        // $this->initDB();
    }

    /**
     * Initializes the PDO connection with database credentials.
     * This is commented out since we're using test data for now.
     */
    private function initDB() {
        $host = 'localhost';
        $dbname = 'my_patients_db';
        $username = 'dbuser';
        $password = 'dbpassword';
        $dsn = "mysql:host={$host};dbname={$dbname};charset=utf8mb4";

        try {
            $this->pdo = new PDO($dsn, $username, $password);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database connection failed: ' . $e->getMessage());
        }
    }

    /**
     * Routes the request to the appropriate method based on the endpoint.
     */
    public function processRequest() {
        switch ($this->endpoint) {
            case 'login':
                $this->login();
                break;
            case 'validate_token':
                $this->validateToken();
                break;
            case 'logout':
                $this->logout();
                break;
            default:
                $this->notFound();
                break;
        }
    }

    /**
     * Handles login requests.
     */
    private function login() {
        $input = json_decode(file_get_contents('php://input'), true);

        if (!$input || !isset($input['email']) || !isset($input['password'])) {
            $this->sendErrorResponse(400, 'Invalid input. Expecting email and password.');
            return;
        }

        $email = $input['email'];
        $password = $input['password'];

        // For testing: valid test credentials (in production, this would check a database)
        $validEmail = "test@gmail.com";
        $validPassword = "Ravee123@#";

        if ($email === $validEmail && $password === $validPassword) {
            // Generate a unique session ID
            $sessionId = session_create_id();
            
            // Generate a JWT-like token
            $issuedAt = time();
            $expirationTime = $issuedAt + 3600; // Token valid for 1 hour
            
            $payload = [
                'iat' => $issuedAt,
                'exp' => $expirationTime,
                'user_id' => 1,
                'email' => $email
            ];
            
            // Simple token generation (not secure for production)
            $token = base64_encode(json_encode($payload));
            
            $this->sendSuccessResponse('Login successful', [
                'user' => [
                    'id' => 1,
                    'email' => $email,
                    'name' => 'Test User',
                    'role' => 'doctor'
                ],
                'token' => $token,
                'session_id' => $sessionId,
                'expires_at' => $expirationTime
            ]);
        } else {
            $this->sendErrorResponse(401, 'Invalid credentials');
        }
    }

    /**
     * Validates authentication token.
     */
    private function validateToken() {
        // Get authorization header
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        
        // Check if token exists
        if (empty($authHeader) || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            $this->sendErrorResponse(401, 'No token provided');
            return;
        }
        
        $token = $matches[1];
        
        // Decode token
        try {
            $payload = json_decode(base64_decode($token), true);
            
            // Check if token is expired
            if (!isset($payload['exp']) || $payload['exp'] < time()) {
                $this->sendErrorResponse(401, 'Token expired');
                return;
            }
            
            $this->sendSuccessResponse('Token is valid');
        } catch (Exception $e) {
            $this->sendErrorResponse(401, 'Invalid token');
        }
    }

    /**
     * Handles logout requests.
     */
    private function logout() {
        // In a real implementation, you would invalidate the token in a database
        $this->sendSuccessResponse('Logout successful');
    }

    /**
     * Handles requests to unknown endpoints.
     */
    private function notFound() {
        $this->sendErrorResponse(404, 'Endpoint not found');
    }

    /**
     * Sends a JSON error response.
     * 
     * @param int $statusCode HTTP status code
     * @param string $message Error message
     */
    private function sendErrorResponse($statusCode, $message) {
        http_response_code($statusCode);
        echo json_encode([
            'success' => false,
            'message' => $message
        ]);
        exit;
    }

    /**
     * Sends a JSON success response.
     * 
     * @param string $message Success message
     * @param array $data Additional data to include in the response
     */
    private function sendSuccessResponse($message, $data = []) {
        http_response_code(200);
        $response = [
            'success' => true,
            'message' => $message
        ];
        
        if (!empty($data)) {
            $response = array_merge($response, $data);
        }
        
        echo json_encode($response);
        exit;
    }
}

// Enhanced endpoint extraction for clean URLs
$requestUri = $_SERVER['REQUEST_URI'];
$basePath = '/my_patients_api/';

// Extract endpoint from REQUEST_URI
if (strpos($requestUri, $basePath) !== false) {
    $endpoint = substr($requestUri, strpos($requestUri, $basePath) + strlen($basePath));
    $endpoint = trim($endpoint, '/');
} else {
    $endpoint = '';
}

// If REQUEST_URI doesn't work, try PATH_INFO
if (empty($endpoint) && isset($_SERVER['PATH_INFO'])) {
    $endpoint = trim($_SERVER['PATH_INFO'], '/');
}

// As a fallback, try REDIRECT_URL
if (empty($endpoint) && isset($_SERVER['REDIRECT_URL'])) {
    $redirectUrl = $_SERVER['REDIRECT_URL'];
    if (strpos($redirectUrl, $basePath) !== false) {
        $endpoint = substr($redirectUrl, strpos($redirectUrl, $basePath) + strlen($basePath));
        $endpoint = trim($endpoint, '/');
    }
}

// For debugging only (comment out in production)
error_log("Endpoint: " . $endpoint);

// Instantiate API class and process request
$api = new ApiHandler($endpoint);
$api->processRequest();
?>