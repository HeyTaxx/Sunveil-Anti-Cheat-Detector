<?php
header('Content-Type: application/json');
require_once 'db_config.php'; // Ensure you renamed the template!

// 1. Security Check: Verify API Key
$headers = getallheaders();
$apiKey = $headers['X-API-Key'] ?? '';

// Simple constant time string comparison to prevent timing attacks
if (!hash_equals(AC_API_KEY, $apiKey)) {
    http_response_code(401);
    die(json_encode(['error' => 'Unauthorized. Invalid API Key.']));
}

// 2. Receive and Parse JSON Payload
$rawPostData = file_get_contents("php://input");
$data = json_decode($rawPostData, true);

if (!$data || !isset($data['player_name'], $data['hwid'], $data['flags'])) {
    http_response_code(400);
    die(json_encode(['error' => 'Bad Request. Invalid JSON payload.']));
}

// 3. Database Connection
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($mysqli->connect_error) {
    http_response_code(500);
    die(json_encode(['error' => 'Database connection failed.']));
}

// 4. Insert Data (Prepared Statements prevent SQL Injection)
$stmt = $mysqli->prepare("INSERT INTO reports (report_id, player_name, hwid, source, signature_match, severity, evidence_dump) VALUES (?, ?, ?, ?, ?, ?, ?)");

$reportId = uniqid('ACD-');
$player = $data['player_name'];
$hwid = $data['hwid'];

$successCount = 0;

foreach ($data['flags'] as $flag) {
    $source = $flag['module'] ?? 'Unknown';
    $signature = $flag['title'] ?? 'Generic Match';
    $severity = $flag['severity'] ?? 'Low';
    $evidence = $flag['evidence'] ?? 'No evidence provided.';

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
