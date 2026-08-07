<?php
header('Content-Type: application/json');
require_once 'db_config.php'; // Ensure you renamed the template!

// 1. Security Check: Verify API Key
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (empty($apiKey) && function_exists('getallheaders')) {
    $headers = getallheaders();
    $apiKey = $headers['X-API-Key'] ?? $headers['x-api-key'] ?? '';
}

// Simple constant time string comparison to prevent timing attacks
if (!is_string($apiKey) || strlen(AC_API_KEY) !== strlen($apiKey) || !hash_equals(AC_API_KEY, $apiKey)) {
    http_response_code(401);
    die(json_encode(['error' => 'Unauthorized. Invalid API Key.']));
}

// 2. Receive and Parse JSON Payload
$rawPostData = file_get_contents("php://input");
$data = json_decode($rawPostData, true);

if (!$data || !isset($data['player_name'], $data['hwid'], $data['flags']) || !is_string($data['player_name']) || !is_string($data['hwid']) || !is_array($data['flags'])) {
    http_response_code(400);
    die(json_encode(['error' => 'Bad Request. Invalid JSON payload or missing fields.']));
}

// 3. Database Connection
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, defined('DB_PORT') ? DB_PORT : 3306);
if ($mysqli->connect_error) {
    http_response_code(500);
    die(json_encode(['error' => 'Database connection failed.']));
}

// 4. Insert Data (Prepared Statements prevent SQL Injection)
$stmt = $mysqli->prepare("INSERT INTO reports (report_id, player_name, hwid, source, signature_match, severity, evidence_dump) VALUES (?, ?, ?, ?, ?, ?, ?)");

$reportId = 'ACD-' . bin2hex(random_bytes(16));
$player = $data['player_name'];
$hwid = $data['hwid'];

$successCount = 0;

foreach ($data['flags'] as $flag) {
    $source = isset($flag['module']) && is_string($flag['module']) ? $flag['module'] : 'Unknown';
    $signature = isset($flag['title']) && is_string($flag['title']) ? $flag['title'] : 'Generic Match';
    $severity = isset($flag['severity']) && is_string($flag['severity']) ? $flag['severity'] : 'Low';
    $evidence = isset($flag['evidence']) && is_string($flag['evidence']) ? $flag['evidence'] : 'No evidence provided.';

    $stmt->bind_param("sssssss", $reportId, $player, $hwid, $source, $signature, $severity, $evidence);
    
    if ($stmt->execute()) {
        $successCount++;
    }
}

$stmt->close();
$mysqli->close();

echo json_encode([
    'success' => true,
    'message' => "$successCount flags inserted.",
    'report_id' => $reportId
]);
?>
