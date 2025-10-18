<?php
function base64url($data){ return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
function jwt_sign($payload, $secret){
  $header = ['alg'=>'HS256','typ'=>'JWT'];
  $segments = [ base64url(json_encode($header)), base64url(json_encode($payload)) ];
  $sig = hash_hmac('sha256', implode('.', $segments), $secret, true);
  $segments[] = base64url($sig);
  return implode('.', $segments);
}
function jwt_verify($jwt, $secret){
  $parts = explode('.', $jwt);
  if(count($parts)!==3) return null;
  list($h,$p,$s) = $parts;
  $check = base64url(hash_hmac('sha256', "$h.$p", $secret, true));
  if(!hash_equals($check, $s)) return null;
  $payload = json_decode(base64_decode(strtr($p, '-_', '+/')), true);
  if(isset($payload['exp']) && time() >= $payload['exp']) return null;
  return $payload;
}
function require_bearer($secret, $roles = null){
  $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
  if(!preg_match('/Bearer\\s+(.+)/i', $hdr, $m)){ http_response_code(401); echo json_encode(['error'=>'Missing Bearer']); exit; }
  $payload = jwt_verify($m[1], $secret);
  if(!$payload){ http_response_code(401); echo json_encode(['error'=>'Invalid token']); exit; }
  if($roles && !in_array($payload['role'], (array)$roles)){ http_response_code(403); echo json_encode(['error'=>'Forbidden']); exit; }
  return $payload;
}
