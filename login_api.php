<?php
// Set headers to allow cross-origin requests and specify JSON
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json; charset=UTF-8");

// Get the request data
$data = json_decode(file_get_contents("php://input"), true);

// Predefined credentials (in a real app, these would come from a database)
$validEmail = "test@test.com";
$validPassword = "123456";

// Default response
$response = [
    "success" => false,
    "message" => "Invalid credentials"
];

// Check if the request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = [
        "success" => false,
        "message" => "Invalid request method"
    ];
    echo json_encode($response);
    exit;
}

// Check if email and password are set
if (isset($data['email']) && isset($data['password'])) {
    $email = $data['email'];
    $password = $data['password'];
    
    // Validate credentials
    if ($email === $validEmail && $password === $validPassword) {
        // Generate a unique session ID
        $sessionId = session_create_id();
        
        // Generate a JWT-like token (in a real app, use a proper JWT library)
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
        
        $response = [
            "success" => true,
            "message" => "Login successful",
            "user" => [
                "id" => 1,
                "email" => $email,
                "name" => "Test User",
                "role" => "doctor"
            ],
            "token" => $token,
            "session_id" => $sessionId,
            "expires_at" => $expirationTime
        ];
        
        // In a real application, you would store the session in a database
        // session_id => user_id, expiration_time, status, etc.
    }
}

// Return the response as JSON
echo json_encode($response);
?>