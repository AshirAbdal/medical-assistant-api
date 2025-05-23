<?php
// Start of session configuration for better persistence
ini_set('session.gc_maxlifetime', 86400); // Set session lifetime to 24 hours
ini_set('session.cookie_lifetime', 86400); // Set cookie lifetime to 24 hours
ini_set('session.use_cookies', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.use_strict_mode', 0); // Allow explicitly set session IDs
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 0); // Set to 1 for HTTPS only
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_trans_sid', 0);
// End of session configuration

// Start session at the beginning of the script
if (session_status() === PHP_SESSION_NONE) {
    session_start();
    
    // Check for session ID in header and use it
    $headers = getallheaders();
    $requestSessionId = isset($headers['X-Session-ID']) ? $headers['X-Session-ID'] : '';
    
    if (!empty($requestSessionId)) {
        // Close current session if it's different
        if (session_id() !== $requestSessionId) {
            session_write_close();
            session_id($requestSessionId);
            session_start();
        }
        
        // Debug information
        error_log("Using provided session ID: " . $requestSessionId);
        error_log("Current PHP session ID: " . session_id());
        error_log("Session data: " . json_encode($_SESSION));
    }
}

// Modified CORS headers to allow cookies
header("Access-Control-Allow-Origin: *"); // In production, specify your domain instead of *
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-ID, Cookie");
header("Access-Control-Allow-Credentials: true");  // IMPORTANT: Allow credentials
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight (OPTIONS) requests automatically
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

class ApiHandler {
    private $endpoint;
    private $pdo;

    /**
     * Constructor: Assigns the API endpoint and initializes the PDO connection.
     *
     * @param string $endpoint Extracted API endpoint from the URL.
     */
    public function __construct($endpoint) {
        $this->endpoint = $endpoint;
        $this->initDB();
    }

    /**
     * Initializes the PDO connection with database credentials.
     */
    private function initDB() {
        $host = 'localhost';
        $dbname = 'my_patients_db';
        $username = 'root';     // Use root user
        $password = '';         // Empty password
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
        $method = $_SERVER['REQUEST_METHOD'];
        
        // Split the endpoint to extract resource and ID
        $parts = explode('/', $this->endpoint);
        $resource = $parts[0];
        $id = isset($parts[1]) ? $parts[1] : null;
        
        switch ($resource) {
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
                if ($method === 'GET') {
                    if ($id) {
                        $this->getPatientById($id);
                    } else {
                        $this->getPatients();
                    }
                } elseif ($method === 'POST') {
                    $this->addPatient();
                } elseif ($method === 'PUT') {
                    $this->updatePatient($id);
                } elseif ($method === 'DELETE') {
                    $this->deletePatient($id);
                }
                break;
            case 'categories':
                if ($method === 'GET') {
                    $this->getCategories();
                }
                break;
            case 'appointments':
                if ($method === 'GET') {
                    if ($id) {
                        $this->getAppointmentById($id);
                    } else {
                        $this->getAppointments();
                    }
                } elseif ($method === 'POST') {
                    $this->addAppointment();
                } elseif ($method === 'PUT') {
                    $this->updateAppointment($id);
                } elseif ($method === 'DELETE') {
                    $this->deleteAppointment($id);
                }
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

        try {
            // Get user by email
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // For testing - direct string comparison 
            // In production, you should use password_verify()
            if ($user && $password === $user['password']) {
                // Start a fresh session
                if (session_status() === PHP_SESSION_ACTIVE) {
                    session_regenerate_id(true);
                }
                
                // Store user data in PHP session
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['name'] = $user['name'];
                $_SESSION['role'] = $user['role'];
                
                // Get the PHP session ID
                $sid = session_id();
                
                // Debug session data
                error_log("Login successful for user ID: " . $user['id']);
                error_log("Session ID after login: " . $sid);
                error_log("Session data: " . json_encode($_SESSION));
                
                // Force session data to be written
                session_write_close();
                session_id($sid);
                session_start();
                
                // Get doctor categories
                $categories = $this->getDoctorCategories($user['id']);
                
                $userData = [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'name' => $user['name'],
                    'role' => $user['role'],
                    'categories' => $categories
                ];
                
                $this->sendSuccessResponse('Login successful', [
                    'user' => $userData,
                    'sid' => $sid
                ]);
            } else {
                $this->sendErrorResponse(401, 'Invalid credentials');
            }
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }
    
    /**
     * Get categories assigned to a doctor
     */
    private function getDoctorCategories($doctorId) {
        $stmt = $this->pdo->prepare("
            SELECT c.id, c.name, c.description 
            FROM categories c
            INNER JOIN doctor_categories dc ON c.id = dc.category_id
            WHERE dc.doctor_id = ?
        ");
        $stmt->execute([$doctorId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Validates the session.
     */
    private function validateSession() {
        // Get session ID from request header
        $headers = getallheaders();
        $requestSessionId = isset($headers['X-Session-ID']) ? $headers['X-Session-ID'] : '';
        
        error_log("Validate session - Request session ID: $requestSessionId");
        error_log("Validate session - Current PHP session ID: " . session_id());
        error_log("Validate session - User ID in session: " . ($_SESSION['user_id'] ?? 'not set'));
        
        // Check if session ID is valid
        if (empty($requestSessionId)) {
            $this->sendErrorResponse(401, 'No session ID provided');
            return;
        }
        
        // IMPORTANT FIX: Always try to use the session ID from header
        if ($requestSessionId !== session_id()) {
            // Close current session
            session_write_close();
            
            // Set session ID to the one from header
            session_id($requestSessionId);
            
            // Restart session
            session_start();
            
            error_log("Validate session - After restart - session ID: " . session_id());
            error_log("Validate session - After restart - User ID: " . ($_SESSION['user_id'] ?? 'still not set'));
        }
        
        // Now check if user is authenticated in this session
        if (!isset($_SESSION['user_id'])) {
            $this->sendErrorResponse(401, 'Invalid or expired session');
            return;
        }
        
        // Add this: Make sure session info is saved
        session_write_close();
        session_id($requestSessionId);
        session_start();
        
        // Get doctor categories
        $categories = $this->getDoctorCategories($_SESSION['user_id']);
        
        // Session is valid, return user data
        $this->sendSuccessResponse('Session is valid', [
            'user' => [
                'id' => $_SESSION['user_id'],
                'email' => $_SESSION['email'],
                'name' => $_SESSION['name'],
                'role' => $_SESSION['role'],
                'categories' => $categories
            ]
        ]);
    }

    /**
     * Retrieves all available categories.
     */
    private function getCategories() {
        if (!$this->validateAuth()) {
            return;
        }
        
        try {
            $stmt = $this->pdo->query("SELECT * FROM categories ORDER BY name");
            $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $this->sendSuccessResponse('Categories retrieved successfully', [
                'categories' => $categories
            ]);
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Retrieves patient data with optional category filtering.
     */
    private function getPatients() {
        if (!$this->validateAuth()) {
            return;
        }
        
        try {
            $doctorId = $_SESSION['user_id'];
            
            // First, get the doctor's assigned categories
            $categoriesStmt = $this->pdo->prepare("
                SELECT category_id FROM doctor_categories 
                WHERE doctor_id = ?
            ");
            $categoriesStmt->execute([$doctorId]);
            $doctorCategoryIds = $categoriesStmt->fetchAll(PDO::FETCH_COLUMN);
            
            // Check if we have any category IDs
            if (empty($doctorCategoryIds)) {
                // If no categories, return only patients created by this doctor
                $query = "
                    SELECT DISTINCT p.*, 
                           GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name,
                           (SELECT category_id FROM patient_categories WHERE patient_id = p.id LIMIT 1) as category_id
                    FROM patients p
                    LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                    LEFT JOIN categories c ON pc.category_id = c.id
                    WHERE p.created_by = ?
                    GROUP BY p.id
                ";
                $params = [$doctorId];
            } else {
                // If we have categories, create placeholders for the IN clause
                $categoryPlaceholders = implode(',', array_fill(0, count($doctorCategoryIds), '?'));
                
                // Build query to get patients matching doctor's categories OR created by this doctor
                $query = "
                    SELECT DISTINCT p.*, 
                           GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name,
                           (SELECT category_id FROM patient_categories WHERE patient_id = p.id LIMIT 1) as category_id
                    FROM patients p
                    LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                    LEFT JOIN categories c ON pc.category_id = c.id
                    WHERE p.id IN (
                        SELECT DISTINCT patient_id 
                        FROM patient_categories 
                        WHERE category_id IN ($categoryPlaceholders)
                    ) OR p.created_by = ?
                    GROUP BY p.id
                ";
                
                // Parameters for the query
                $params = array_merge($doctorCategoryIds, [$doctorId]);
            }
            
            // Filter by category_id if provided
            if (isset($_GET['category_id']) && $_GET['category_id']) {
                $categoryId = (int)$_GET['category_id'];
                $query = "
                    SELECT DISTINCT p.*, 
                           GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name,
                           (SELECT category_id FROM patient_categories WHERE patient_id = p.id LIMIT 1) as category_id
                    FROM patients p
                    LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                    LEFT JOIN categories c ON pc.category_id = c.id
                    WHERE p.id IN (
                        SELECT patient_id 
                        FROM patient_categories 
                        WHERE category_id = ?
                    )
                    GROUP BY p.id
                ";
                $params = [$categoryId];
            }
            
            $query .= " ORDER BY p.name";
            
            // Debug information
            error_log("Patient query: $query");
            error_log("Patient params: " . json_encode($params));
            
            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Debug information
            error_log("Patients found: " . count($patients));
            
            // Get upcoming appointments
            $appointments = $this->getUpcomingAppointments($doctorId);
            
            $this->sendSuccessResponse('Patients retrieved successfully', [
                'patients' => $patients,
                'appointments' => $appointments
            ]);
        } catch (PDOException $e) {
            error_log("Database error in getPatients: " . $e->getMessage());
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }
    
    /**
     * Retrieves a single patient by ID.
     */
    private function getPatientById($id) {
        if (!$this->validateAuth()) {
            return;
        }
        
        try {
            $doctorId = $_SESSION['user_id'];
            
            $stmt = $this->pdo->prepare("
                SELECT p.*, 
                       GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name
                FROM patients p
                LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                LEFT JOIN categories c ON pc.category_id = c.id
                WHERE p.id = ? AND p.created_by = ?
                GROUP BY p.id
            ");
            $stmt->execute([$id, $doctorId]);
            $patient = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$patient) {
                $this->sendErrorResponse(404, 'Patient not found');
                return;
            }
            
            // Get patient appointments
            $stmt = $this->pdo->prepare("
                SELECT * FROM appointments 
                WHERE patient_id = ? AND doctor_id = ?
                ORDER BY appointment_date DESC, appointment_time DESC
            ");
            $stmt->execute([$id, $doctorId]);
            $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $this->sendSuccessResponse('Patient retrieved successfully', [
                'patient' => $patient,
                'appointments' => $appointments
            ]);
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Gets upcoming appointments for a doctor.
     */
    private function getUpcomingAppointments($doctorId) {
        $stmt = $this->pdo->prepare("
            SELECT a.id, a.appointment_date, a.appointment_time, a.type, a.status,
                   p.id as patient_id, p.name as patient_name, p.gender,
                   GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name,
                   (SELECT category_id FROM patient_categories WHERE patient_id = p.id LIMIT 1) as category_id
            FROM appointments a
            INNER JOIN patients p ON a.patient_id = p.id
            LEFT JOIN patient_categories pc ON p.id = pc.patient_id
            LEFT JOIN categories c ON pc.category_id = c.id
            WHERE a.doctor_id = ? 
              AND a.status = 'scheduled'
              AND (a.appointment_date > CURDATE() 
                   OR (a.appointment_date = CURDATE() AND a.appointment_time >= CURTIME()))
            GROUP BY a.id
            ORDER BY a.appointment_date, a.appointment_time
            LIMIT 5
        ");
        $stmt->execute([$doctorId]);
        
        $appointments = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            // Format for the frontend
            $appointments[] = [
                'id' => $row['id'],
                'time' => date('h:i A', strtotime($row['appointment_time'])),
                'date' => date('Y-m-d', strtotime($row['appointment_date'])),
                'name' => $row['patient_name'],
                'type' => $row['type'],
                'category' => $row['category_name'],
                'color' => $row['category_id'] % 2 == 0 ? '#4CAF50' : '#2196F3', // Alternate colors based on category
                'patient_id' => $row['patient_id']
            ];
        }
        
        return $appointments;
    }

    /**
     * Adds a new patient.
     */
    private function addPatient() {
        if (!$this->validateAuth()) {
            return;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['name'])) {
            $this->sendErrorResponse(400, 'Invalid input. Patient name is required.');
            return;
        }
        
        try {
            // Start transaction
            $this->pdo->beginTransaction();
            
            // Get the next patient ID
            $stmt = $this->pdo->query("SELECT MAX(CAST(SUBSTRING(patient_id, 2) AS UNSIGNED)) as max_id FROM patients");
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $nextId = ($result['max_id'] ?? 1000) + 1;
            $patientId = 'P' . $nextId;
            
            // Insert patient (without category_id)
            $stmt = $this->pdo->prepare("
                INSERT INTO patients (
                    patient_id, name, age, gender, email, phone, address, 
                    medical_history, notes, created_by
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ");
            
            $stmt->execute([
                $patientId,
                $input['name'],
                $input['age'] ?? null,
                $input['gender'] ?? null,
                $input['email'] ?? null,
                $input['phone'] ?? null,
                $input['address'] ?? null,
                $input['medical_history'] ?? null,
                $input['notes'] ?? null,
                $_SESSION['user_id']
            ]);
            
            $newPatientId = $this->pdo->lastInsertId();
            
            // If category_id is provided, insert into patient_categories
            if (isset($input['category_id']) && $input['category_id']) {
                $stmt = $this->pdo->prepare("
                    INSERT INTO patient_categories (patient_id, category_id)
                    VALUES (?, ?)
                ");
                $stmt->execute([$newPatientId, $input['category_id']]);
            }
            
            // Commit transaction
            $this->pdo->commit();
            
            // Get the created patient data
            $stmt = $this->pdo->prepare("
                SELECT p.*, 
                       GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name
                FROM patients p
                LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                LEFT JOIN categories c ON pc.category_id = c.id
                WHERE p.id = ?
                GROUP BY p.id
            ");
            $stmt->execute([$newPatientId]);
            $patient = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $this->sendSuccessResponse('Patient added successfully', [
                'patient' => $patient
            ]);
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Updates an existing patient.
     */
    private function updatePatient($id) {
        if (!$this->validateAuth()) {
            return;
        }
        
        if (!$id) {
            $this->sendErrorResponse(400, 'Patient ID is required.');
            return;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            $this->sendErrorResponse(400, 'Invalid input data.');
            return;
        }
        
        try {
            // Start transaction
            $this->pdo->beginTransaction();
            
            // Verify the patient belongs to this doctor
            $stmt = $this->pdo->prepare("SELECT * FROM patients WHERE id = ? AND created_by = ?");
            $stmt->execute([$id, $_SESSION['user_id']]);
            $patient = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$patient) {
                $this->sendErrorResponse(404, 'Patient not found or you don\'t have permission to update.');
                return;
            }
            
            // Build the update query dynamically based on provided fields
            $updateFields = [];
            $params = [];
            
            $allowedFields = [
                'name', 'age', 'gender', 'email', 'phone', 'address', 
                'medical_history', 'notes'
            ];
            
            foreach ($allowedFields as $field) {
                if (isset($input[$field])) {
                    $updateFields[] = "$field = ?";
                    $params[] = $input[$field];
                }
            }
            
            if (!empty($updateFields)) {
                // Add patient ID to params
                $params[] = $id;
                
                $query = "UPDATE patients SET " . implode(', ', $updateFields) . " WHERE id = ?";
                $stmt = $this->pdo->prepare($query);
                $stmt->execute($params);
            }
            
            // Handle category update separately
            if (isset($input['category_id'])) {
                // Delete existing categories
                $stmt = $this->pdo->prepare("DELETE FROM patient_categories WHERE patient_id = ?");
                $stmt->execute([$id]);
                
                // Add new category if provided
                if ($input['category_id']) {
                    $stmt = $this->pdo->prepare("
                        INSERT INTO patient_categories (patient_id, category_id)
                        VALUES (?, ?)
                    ");
                    $stmt->execute([$id, $input['category_id']]);
                }
            }
            
            // Commit transaction
            $this->pdo->commit();
            
            // Get updated patient data
            $stmt = $this->pdo->prepare("
                SELECT p.*, 
                       GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name
                FROM patients p
                LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                LEFT JOIN categories c ON pc.category_id = c.id
                WHERE p.id = ?
                GROUP BY p.id
            ");
            $stmt->execute([$id]);
            $updatedPatient = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $this->sendSuccessResponse('Patient updated successfully', [
                'patient' => $updatedPatient
            ]);
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Deletes a patient.
     */
    private function deletePatient($id) {
        if (!$this->validateAuth()) {
            return;
        }
        
        if (!$id) {
            $this->sendErrorResponse(400, 'Patient ID is required.');
            return;
        }
        
        try {
            // Verify the patient belongs to this doctor
            $stmt = $this->pdo->prepare("SELECT * FROM patients WHERE id = ? AND created_by = ?");
            $stmt->execute([$id, $_SESSION['user_id']]);
            $patient = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$patient) {
                $this->sendErrorResponse(404, 'Patient not found or you don\'t have permission to delete.');
                return;
            }
            
            // Delete the patient (appointments and patient_categories will be cascaded)
            $stmt = $this->pdo->prepare("DELETE FROM patients WHERE id = ?");
            $stmt->execute([$id]);
            
            $this->sendSuccessResponse('Patient deleted successfully');
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Retrieves appointments with optional filtering.
     */
    private function getAppointments() {
        if (!$this->validateAuth()) {
            return;
        }
        
        try {
            $doctorId = $_SESSION['user_id'];
            
            // Check for date filter from query string
            $date = isset($_GET['date']) ? $_GET['date'] : null;
            $patientId = isset($_GET['patient_id']) ? (int)$_GET['patient_id'] : null;
            
            // Base query
            $query = "
                SELECT a.*, 
                       p.name as patient_name, p.patient_id as patient_code, p.gender,
                       GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name
                FROM appointments a
                INNER JOIN patients p ON a.patient_id = p.id
                LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                LEFT JOIN categories c ON pc.category_id = c.id
                WHERE a.doctor_id = ?
            ";
            $params = [$doctorId];
            
            // Add filters if specified
            if ($date) {
                $query .= " AND a.appointment_date = ?";
                $params[] = $date;
            }
            
            if ($patientId) {
                $query .= " AND a.patient_id = ?";
                $params[] = $patientId;
            }
            
            $query .= " GROUP BY a.id ORDER BY a.appointment_date, a.appointment_time";
            
            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Format appointments for frontend
            $formattedAppointments = [];
            foreach ($appointments as $appointment) {
                $formattedAppointments[] = [
                    'id' => $appointment['id'],
                    'time' => date('h:i A', strtotime($appointment['appointment_time'])),
                    'date' => $appointment['appointment_date'],
                    'name' => $appointment['patient_name'],
                    'patient_id' => $appointment['patient_id'],
                    'patient_code' => $appointment['patient_code'],
                    'type' => $appointment['type'],
                    'status' => $appointment['status'],
                    'notes' => $appointment['notes'],
                    'category' => $appointment['category_name'],
                    'color' => $appointment['id'] % 2 == 0 ? '#4CAF50' : '#2196F3' // Alternate colors
                ];
            }
            
            $this->sendSuccessResponse('Appointments retrieved successfully', [
                'appointments' => $formattedAppointments
            ]);
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Retrieves a single appointment by ID.
     */
    private function getAppointmentById($id) {
        if (!$this->validateAuth()) {
            return;
        }
        
        try {
            $doctorId = $_SESSION['user_id'];
            
            $stmt = $this->pdo->prepare("
                SELECT a.*, 
                       p.name as patient_name, p.patient_id as patient_code, p.gender,
                       GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name
                FROM appointments a
                INNER JOIN patients p ON a.patient_id = p.id
                LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                LEFT JOIN categories c ON pc.category_id = c.id
                WHERE a.id = ? AND a.doctor_id = ?
                GROUP BY a.id
            ");
            $stmt->execute([$id, $doctorId]);
            $appointment = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$appointment) {
                $this->sendErrorResponse(404, 'Appointment not found');
                return;
            }
            
            // Format for frontend
            $formattedAppointment = [
                'id' => $appointment['id'],
                'time' => date('h:i A', strtotime($appointment['appointment_time'])),
                'date' => $appointment['appointment_date'],
                'name' => $appointment['patient_name'],
                'patient_id' => $appointment['patient_id'],
                'patient_code' => $appointment['patient_code'],
                'type' => $appointment['type'],
                'status' => $appointment['status'],
                'notes' => $appointment['notes'],
                'category' => $appointment['category_name'],
                'color' => $appointment['id'] % 2 == 0 ? '#4CAF50' : '#2196F3'
            ];
            
            $this->sendSuccessResponse('Appointment retrieved successfully', [
                'appointment' => $formattedAppointment
            ]);
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Adds a new appointment.
     */
    private function addAppointment() {
        if (!$this->validateAuth()) {
            return;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['patient_id']) || !isset($input['appointment_date']) || 
            !isset($input['appointment_time']) || !isset($input['type'])) {
            $this->sendErrorResponse(400, 'Invalid input. Required fields: patient_id, appointment_date, appointment_time, type');
            return;
        }
        
        try {
            // Verify the patient belongs to this doctor
            $stmt = $this->pdo->prepare("SELECT * FROM patients WHERE id = ? AND created_by = ?");
            $stmt->execute([$input['patient_id'], $_SESSION['user_id']]);
            $patient = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$patient) {
                $this->sendErrorResponse(404, 'Patient not found or you don\'t have permission.');
                return;
            }
            
            $stmt = $this->pdo->prepare("
                INSERT INTO appointments (
                    patient_id, doctor_id, appointment_date, appointment_time, 
                    type, status, notes
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?
                )
            ");
            
            $stmt->execute([
                $input['patient_id'],
                $_SESSION['user_id'],
                $input['appointment_date'],
                $input['appointment_time'],
                $input['type'],
                $input['status'] ?? 'scheduled',
                $input['notes'] ?? null
            ]);
            
            $newAppointmentId = $this->pdo->lastInsertId();
            
            // Get the created appointment data
            $stmt = $this->pdo->prepare("
                SELECT a.*, 
                       p.name as patient_name, p.patient_id as patient_code, p.gender,
                       GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name
                FROM appointments a
                INNER JOIN patients p ON a.patient_id = p.id
                LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                LEFT JOIN categories c ON pc.category_id = c.id
                WHERE a.id = ?
                GROUP BY a.id
            ");
            $stmt->execute([$newAppointmentId]);
            $appointment = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Format for frontend
            $formattedAppointment = [
                'id' => $appointment['id'],
                'time' => date('h:i A', strtotime($appointment['appointment_time'])),
                'date' => $appointment['appointment_date'],
                'name' => $appointment['patient_name'],
                'patient_id' => $appointment['patient_id'],
                'patient_code' => $appointment['patient_code'],
                'type' => $appointment['type'],
                'status' => $appointment['status'],
                'notes' => $appointment['notes'],
                'category' => $appointment['category_name'],
                'color' => $appointment['id'] % 2 == 0 ? '#4CAF50' : '#2196F3'
            ];
            
            $this->sendSuccessResponse('Appointment added successfully', [
                'appointment' => $formattedAppointment
            ]);
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Updates an existing appointment.
     */
    private function updateAppointment($id) {
        if (!$this->validateAuth()) {
            return;
        }
        
        if (!$id) {
            $this->sendErrorResponse(400, 'Appointment ID is required.');
            return;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            $this->sendErrorResponse(400, 'Invalid input data.');
            return;
        }
        
        try {
            // Verify the appointment belongs to this doctor
            $stmt = $this->pdo->prepare("SELECT * FROM appointments WHERE id = ? AND doctor_id = ?");
            $stmt->execute([$id, $_SESSION['user_id']]);
            $appointment = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$appointment) {
                $this->sendErrorResponse(404, 'Appointment not found or you don\'t have permission to update.');
                return;
            }
            
            // Build the update query dynamically based on provided fields
            $updateFields = [];
            $params = [];
            
            $allowedFields = [
                'patient_id', 'appointment_date', 'appointment_time', 'type', 'status', 'notes'
            ];
            
            foreach ($allowedFields as $field) {
                if (isset($input[$field])) {
                    // If updating patient_id, verify it belongs to this doctor
                    if ($field === 'patient_id') {
                        $patientStmt = $this->pdo->prepare("SELECT * FROM patients WHERE id = ? AND created_by = ?");
                        $patientStmt->execute([$input[$field], $_SESSION['user_id']]);
                        $patient = $patientStmt->fetch(PDO::FETCH_ASSOC);
                        
                        if (!$patient) {
                            $this->sendErrorResponse(404, 'Patient not found or you don\'t have permission.');
                            return;
                        }
                    }
                    
                    $updateFields[] = "$field = ?";
                    $params[] = $input[$field];
                }
            }
            
            if (empty($updateFields)) {
                $this->sendErrorResponse(400, 'No valid fields to update.');
                return;
            }
            
            // Add appointment ID to params
            $params[] = $id;
            
            $query = "UPDATE appointments SET " . implode(', ', $updateFields) . " WHERE id = ?";
            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            
            // Get updated appointment data
            $stmt = $this->pdo->prepare("
                SELECT a.*, 
                       p.name as patient_name, p.patient_id as patient_code, p.gender,
                       GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ') as category_name
                FROM appointments a
                INNER JOIN patients p ON a.patient_id = p.id
                LEFT JOIN patient_categories pc ON p.id = pc.patient_id
                LEFT JOIN categories c ON pc.category_id = c.id
                WHERE a.id = ?
                GROUP BY a.id
            ");
            $stmt->execute([$id]);
            $updatedAppointment = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Format for frontend
            $formattedAppointment = [
                'id' => $updatedAppointment['id'],
                'time' => date('h:i A', strtotime($updatedAppointment['appointment_time'])),
                'date' => $updatedAppointment['appointment_date'],
                'name' => $updatedAppointment['patient_name'],
                'patient_id' => $updatedAppointment['patient_id'],
                'patient_code' => $updatedAppointment['patient_code'],
                'type' => $updatedAppointment['type'],
                'status' => $updatedAppointment['status'],
                'notes' => $updatedAppointment['notes'],
                'category' => $updatedAppointment['category_name'],
                'color' => $updatedAppointment['id'] % 2 == 0 ? '#4CAF50' : '#2196F3'
            ];
            
            $this->sendSuccessResponse('Appointment updated successfully', [
                'appointment' => $formattedAppointment
            ]);
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Deletes an appointment.
     */
    private function deleteAppointment($id) {
        if (!$this->validateAuth()) {
            return;
        }
        
        if (!$id) {
            $this->sendErrorResponse(400, 'Appointment ID is required.');
            return;
        }
        
        try {
            // Verify the appointment belongs to this doctor
            $stmt = $this->pdo->prepare("SELECT * FROM appointments WHERE id = ? AND doctor_id = ?");
            $stmt->execute([$id, $_SESSION['user_id']]);
            $appointment = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$appointment) {
                $this->sendErrorResponse(404, 'Appointment not found or you don\'t have permission to delete.');
                return;
            }
            
            // Delete the appointment
            $stmt = $this->pdo->prepare("DELETE FROM appointments WHERE id = ?");
            $stmt->execute([$id]);
            
            $this->sendSuccessResponse('Appointment deleted successfully');
        } catch (PDOException $e) {
            $this->sendErrorResponse(500, 'Database error: ' . $e->getMessage());
        }
    }

    /**
     * Validates if the user is authenticated.
     */
    private function validateAuth() {
        $headers = getallheaders();
        $requestSessionId = isset($headers['X-Session-ID']) ? $headers['X-Session-ID'] : '';
        
        error_log("Request session ID from header: $requestSessionId");
        error_log("Current PHP session ID: " . session_id());
        error_log("User ID in session: " . ($_SESSION['user_id'] ?? 'not set'));
        
        // If we have a session ID in the header
        if (!empty($requestSessionId)) {
            // If the request session ID is different from the current one,
            // or we don't have a user_id in the current session,
            // try to use the provided session ID
            if ($requestSessionId !== session_id() || empty($_SESSION['user_id'])) {
                // Close the current session
                session_write_close();
                
                // Set the session ID to the one from the header
                session_id($requestSessionId);
                
                // Start the session again with the new ID
                session_start();
                
                error_log("Switched session ID to: $requestSessionId");
                error_log("Session data after switch: " . json_encode($_SESSION));
            }
        }
        
        // Check if the user is authenticated in this session
        if (!isset($_SESSION['user_id'])) {
            error_log("Authentication failed - no user_id in session");
            $this->sendErrorResponse(401, 'Unauthorized. Please log in first.');
            return false;
        }
        
        error_log("Authentication successful for user ID: " . $_SESSION['user_id']);
        return true;
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