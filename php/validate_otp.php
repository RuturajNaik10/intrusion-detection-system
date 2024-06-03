<?php
$otp = $_POST['otp'];
$filePath = "otp.txt";
$fileHandle = fopen($filePath, "r");
$fileContents = fread($fileHandle, filesize($filePath));
fclose($fileHandle);
if($fileContents==$otp){
     header("Location: ../dashboard.html");
    exit;
}
else{
    header("Location: ../forgot.html");
    exit;
}

?>
