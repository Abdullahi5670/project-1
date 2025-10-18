<?php
function json_body(){
  $raw = file_get_contents('php://input');
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}
function send($code, $data){
  http_response_code($code);
  header('Content-Type: application/json');
  echo json_encode($data);
  exit;
}
function path_id($base){
  $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
  $parts = explode('/', trim($uri,'/'));
  $i = array_search(trim($base,'/'), $parts);
  return ($i!==false && isset($parts[$i+1]) && ctype_digit($parts[$i+1])) ? (int)$parts[$i+1] : null;
}
