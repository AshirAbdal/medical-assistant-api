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
        $response = [
            "success" => true,
            "message" => "Login successful",
            "user" => [
                "id" => 1,
                "email" => $email,
                "name" => "Test User",
                "role" => "doctor"
            ]
        ];
    }
}

// Return the response as JSON
echo json_encode($response);
?>