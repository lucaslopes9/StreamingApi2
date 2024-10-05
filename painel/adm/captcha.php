<?php
$codigoCaptcha = substr(md5(uniqid('')),-9,6);
setcookie("CaptchaP", $codigoCaptcha, time()+86400, "/");

$imagemCaptcha = imagecreatefrompng("fundocaptch.png");
$fonteCaptcha = imageloadfont("anonymous.gdf");
$corCaptcha = imagecolorallocate($imagemCaptcha,105,105,105);
imagestring($imagemCaptcha,$fonteCaptcha,50,3,$codigoCaptcha,$corCaptcha);

header("Content-type: image/png");
imagepng($imagemCaptcha);
imagedestroy($imagemCaptcha);
?>