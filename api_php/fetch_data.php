<?php
header('Content-Type: application/json');
require_once 'db_config.php';

// Security Check: Verify API Key
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (empty($apiKey) && function_exists('getallheaders')) {
    $headers = getallheaders();
    $apiKey = $headers['X-API-Key'] ?? $headers['x-api-key'] ?? '';
}

if (!is_string($apiKey) || strlen(AC_API_KEY) !== strlen($apiKey) || !hash_equals(AC_API_KEY, $apiKey)) {
    http_response_code(401);
    die(json_encode(['error' => 'Unauthorized. Invalid API Key.']));
}

$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, defined('DB_PORT') ? DB_PORT : 3306);
if ($mysqli->connect_error) {
    http_response_code(500);
    die(json_encode(['error' => 'Database connection failed.']));
}

// Fetch the 50 most recent flags
$result = $mysqli->query("SELECT * FROM reports ORDER BY created_at DESC LIMIT 50");

$reports = [];
$threatCount = 0;
$uniqueSessions = [];

while ($row = $result->fetch_assoc()) {
    $threatCount++;
    $uniqueSessions[$row['hwid']] = true;
    
    // Map severity to icons and colors
    $severityClass = strtolower($row['severity']) == 'high' ? 'alert' : (strtolower($row['severity']) == 'medium' ? 'orange-500' : 'yellow-500');
    $icon = strpos(strtolower($row['source']), 'file') !== false ? 'fa-hard-drive' : 
           (strpos(strtolower($row['source']), 'ram') !== false || strpos(strtolower($row['source']), 'process') !== false ? 'fa-memory' : 'fa-list-check');

    $reports[] = [
        'id' => $row['report_id'] . '-' . $row['id'], // Unique DOM id
        'player' => htmlspecialchars($row['player_name']),
        'hwid' => htmlspecialchars(substr($row['hwid'], 0, 16)), // Truncate HWID for display
        'source' => htmlspecialchars($row['source']),
        'icon' => $icon,
        'signature' => htmlspecialchars($row['signature_match']),
        'integrity' => 'Verified',
        'code' => htmlspecialchars($row['evidence_dump']),
        'severity' => $severityClass
    ];
}

$mysqli->close();

echo json_encode([
    'stats' => [
        'sessions' => count($uniqueSessions),
        'threats' => $threatCount,
        'integrity' => '100%' // Simulated integrity calculation
    ],
    'reports' => $reports
]);
?>
