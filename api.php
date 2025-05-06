<?php
// Start session at the beginning of the script
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// CORS headers
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-ID"); // Added X-Session-ID
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
            case 'validate_session':
                $this->validateSession();
                break;
            case 'logout':
                $this->logout();
                break;
            case 'patients':
                $this->getPatients();
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
            // Store user data in PHP session
            $_SESSION['user_id'] = 1;
            $_SESSION['email'] = $email;
            $_SESSION['name'] = 'Test User';
            $_SESSION['role'] = 'doctor';
            
            // Get the PHP session ID
            $sid = session_id();
            
            $this->sendSuccessResponse('Login successful', [
                'user' => [
                    'id' => 1,
                    'email' => $email,
                    'name' => 'Test User',
                    'role' => 'doctor'
                ],
                'sid' => $sid
            ]);
        } else {
            $this->sendErrorResponse(401, 'Invalid credentials');
        }
    }

    /**
     * Validates the session.
     */
    private function validateSession() {
        // Get session ID from request header
        $headers = getallheaders();
        $requestSessionId = isset($headers['X-Session-ID']) ? $headers['X-Session-ID'] : '';
        
        // Check if session ID is valid
        if (empty($requestSessionId)) {
            $this->sendErrorResponse(401, 'No session ID provided');
            return;
        }
        
        // Compare with current session ID
        if ($requestSessionId === session_id() && isset($_SESSION['user_id'])) {
            $this->sendSuccessResponse('Session is valid', [
                'user' => [
                    'id' => $_SESSION['user_id'],
                    'email' => $_SESSION['email'],
                    'name' => $_SESSION['name'],
                    'role' => $_SESSION['role']
                ]
            ]);
        } else {
            $this->sendErrorResponse(401, 'Invalid or expired session');
        }
    }

    /**
     * Retrieves patient data for the authenticated user.
     */
    private function getPatients() {
        // Check if this is a GET request
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            $this->sendErrorResponse(405, 'Method not allowed. Use GET for this endpoint.');
            return;
        }
        
        // Get session ID from request header
        $headers = getallheaders();
        $requestSessionId = isset($headers['X-Session-ID']) ? $headers['X-Session-ID'] : '';
        
        // Validate session
        if (empty($requestSessionId) || $requestSessionId !== session_id() || !isset($_SESSION['user_id'])) {
            $this->sendErrorResponse(401, 'Invalid or expired session');
            return;
        }
        
        // Return sample patient data (in production, this would come from a database)
        $patients = [
            [
                'name' => 'John Doe',
                'age' => 45,
                'gender' => 'Male',
                'id' => 'P1001',
                'iconColor' => '#2196F3' // Blue color code
            ],
            [
                'name' => 'Michael Johnson',
                'age' => 68,
                'gender' => 'Male',
                'id' => 'P1003',
                'iconColor' => '#2196F3'
            ],
            [
                'name' => 'David Wilson',
                'age' => 55,
                'gender' => 'Male',
                'id' => 'P1005',
                'iconColor' => '#2196F3'
            ]
        ];
        
        // Sample appointments data
        $appointments = [
            [
                'time' => '02:15 PM',
                'name' => 'David Wilson',
                'type' => 'Consultation',
                'color' => '#2196F3' // Blue color code
            ],
            [
                'time' => '09:30 AM',
                'name' => 'John Doe',
                'type' => 'Check-up',
                'color' => '#4CAF50' // Green color code
            ]
        ];
        
        $this->sendSuccessResponse('Patients retrieved successfully', [
            'patients' => $patients,
            'appointments' => $appointments
        ]);
    }

    /**
     * Handles logout requests.
     */
    private function logout() {
        // Clear session data
        session_unset();
        
        // Destroy the session
        session_destroy();
        
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