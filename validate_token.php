<?php
// validate_token.php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=UTF-8");

// Get the request data
$data = json_decode(file_get_contents("php://input"), true);
$headers = getallheaders();

// Default response
$response = [
    "success" => false,
    "message" => "Invalid token"
];

// Check if Authorization header is present
if (isset($headers['Authorization'])) {
    $authHeader = $headers['Authorization'];
    
    // Extract the token (Bearer token format)
    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $token = $matches[1];
        
        // Decode the token
        $payload = json_decode(base64_decode($token), true);
        
        // Check if token is valid and not expired
        if ($payload && isset($payload['exp']) && $payload['exp'] > time()) {
            $response = [
                "success" => true,
                "message" => "Token is valid",
                "user_id" => $payload['user_id']
            ];
        } else {
            $response["message"] = "Token expired";
        }
    }
}

echo json_encode($response);
?>