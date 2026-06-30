<?php
// SQLi test corpus for GS005 — PHP patterns.
// Every uncommented line should be detected.

// POSITIVE — mysqli
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
mysqli_query($conn, "SELECT * FROM orders WHERE status = '" . $status . "'");

// POSITIVE — PDO
$pdo->query("SELECT * FROM orders WHERE status = '" . $status . "'");
$pdo->query("SELECT * FROM users WHERE email = '{$email}'");

// POSITIVE — pg
pg_query($conn, "SELECT * FROM data WHERE key = '" . $key . "'");

// POSITIVE — Laravel
DB::table('users')->whereRaw("email = '{$email}'")->get();
DB::select("SELECT * FROM logs WHERE user_id = {$userId}");
