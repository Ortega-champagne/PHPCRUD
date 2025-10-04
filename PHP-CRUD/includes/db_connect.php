<?php
$host - "localhost";
$user "root"; // default XAMPP user
$pass - " "; // default XAMPP password is empty
$db  = "cud";

$Sconn = new mysqli($Shost, $Suser, $Spass, $Sdb);

if ($conn->connect_error) {
die("Connection failed: " . $Sconn->connect_error);
}
?>