<?php
function handle_register($pdo){
  $b = json_body();
  if (!isset($b['name'],$b['email'],$b['password'])) send(400,['error'=>'name/email/password required']);
  $hash = password_hash($b['password'], PASSWORD_BCRYPT);
  $role = 'student';
  $stmt = $pdo->prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)");
  try { $stmt->execute([$b['name'],$b['email'],$hash,$role]); }
  catch(PDOException $e){ send(409,['error'=>'email exists']); }
  send(201,['id'=>$pdo->lastInsertId(),'name'=>$b['name'],'email'=>$b['email'],'role'=>$role]);
}

function handle_login($pdo, $secret){
  $b = json_body();
  $stmt = $pdo->prepare("SELECT * FROM users WHERE email=?");
  $stmt->execute([$b['email']??'']);
  $u = $stmt->fetch(PDO::FETCH_ASSOC);
  if(!$u || !password_verify(($b['password']??''), $u['password_hash'])) send(401,['error'=>'invalid credentials']);
  $payload = ['id'=>$u['id'],'email'=>$u['email'],'role'=>$u['role'],'exp'=>time()+60*60*4];
  $token = jwt_sign($payload, $secret);
  send(200,['token'=>$token,'user'=>['id'=>$u['id'],'name'=>$u['name'],'email'=>$u['email'],'role'=>$u['role']]]);
}

function handle_users($pdo, $secret){
  $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
  $method = $_SERVER['REQUEST_METHOD'];
  $id = path_id('/users');

  // GET /users
  if ($uri==='/users' && $method==='GET'){
    $stmt = $pdo->query("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC");
    send(200, $stmt->fetchAll(PDO::FETCH_ASSOC));
  }

  // GET /users/{id}
  if ($id && $method==='GET'){
    $stmt = $pdo->prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?");
    $stmt->execute([$id]);
    $u = $stmt->fetch(PDO::FETCH_ASSOC);
    if(!$u) send(404,['error'=>'not found']);
    send(200,$u);
  }

  // POST /users (admin only)
  if ($uri==='/users' && $method==='POST'){
    $claims = require_bearer($secret, ['admin']);
    $b = json_body();
    if (!isset($b['name'],$b['email'],$b['password'],$b['role'])) send(400,['error'=>'missing fields']);
    $hash = password_hash($b['password'], PASSWORD_BCRYPT);
    $stmt = $pdo->prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)");
    try { $stmt->execute([$b['name'],$b['email'],$hash,$b['role']]); }
    catch(PDOException $e){ send(409,['error'=>'email exists']); }
    send(201,['id'=>$pdo->lastInsertId()]);
  }

  // PUT /users/{id} (self or admin)
  if ($id && $method==='PUT'){
    $claims = require_bearer($secret, ['student','instructor','admin']);
    if($claims['role']!=='admin' && (int)$claims['id']!==$id){ send(403,['error'=>'Forbidden']); }
    $b = json_body();
    $fields = []; $args=[];
    if(isset($b['name'])) { $fields[]='name=?'; $args[]=$b['name']; }
    if(isset($b['email'])){ $fields[]='email=?'; $args[]=$b['email']; }
    if(isset($b['password'])){ $fields[]='password_hash=?'; $args[]=password_hash($b['password'], PASSWORD_BCRYPT); }
    if(isset($b['role']) && $claims['role']==='admin'){ $fields[]='role=?'; $args[]=$b['role']; }
    if(empty($fields)) send(400,['error'=>'no fields']);
    $args[]=$id;
    $stmt = $pdo->prepare("UPDATE users SET ".implode(',', $fields)." WHERE id=?");
    $stmt->execute($args);
    send(200,['updated'=>true]);
  }

  // DELETE /users/{id} (admin only)
  if ($id && $method==='DELETE'){
    $claims = require_bearer($secret, ['admin']);
    $stmt = $pdo->prepare("DELETE FROM users WHERE id=?");
    $stmt->execute([$id]);
    send(200,['deleted'=>($stmt->rowCount()>0)]);
  }

  // GET /users/me
  if ($uri==='/users/me' && $method==='GET'){
    $claims = require_bearer($secret);
    $stmt=$pdo->prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?");
    $stmt->execute([$claims['id']]);
    send(200,$stmt->fetch(PDO::FETCH_ASSOC));
  }

  // PUT /users/me
  if ($uri==='/users/me' && $method==='PUT'){
    $claims = require_bearer($secret);
    $b = json_body();
    $fields=[]; $args=[];
    if(isset($b['name'])){ $fields[]='name=?'; $args[]=$b['name']; }
    if(isset($b['password'])){ $fields[]='password_hash=?'; $args[]=password_hash($b['password'], PASSWORD_BCRYPT); }
    if(empty($fields)) send(400,['error'=>'no fields']);
    $args[]=$claims['id'];
    $stmt=$pdo->prepare("UPDATE users SET ".implode(',', $fields)." WHERE id=?");
    $stmt->execute($args);
    send(200,['updated'=>true]);
  }
}
