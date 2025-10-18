<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Authorization, Content-Type');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
if ($_SERVER['REQUEST_METHOD']==='OPTIONS') { http_response_code(204); exit; }

require __DIR__.'/db.php';
require __DIR__.'/auth.php';
require __DIR__.'/util.php';
require __DIR__.'/users.php';

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];
$secret = getenv('JWT_SECRET') ?: 'change-this-secret';

// Auth
if ($uri==='/auth/register' && $method==='POST') { handle_register($pdo); }
if ($uri==='/auth/login'    && $method==='POST') { handle_login($pdo, $secret); }

// Users
if (preg_match('#^/users(?:/.*)?$#', $uri)) { handle_users($pdo, $secret); }

// 404
send(404, ['error'=>'Not Found']);
