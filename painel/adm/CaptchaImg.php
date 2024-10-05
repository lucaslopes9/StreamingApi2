<?php
$CC = substr(md5(uniqid('')),-9,6);
echo "<img src=\"captcha.php?c=".time().$CC."\" />";
?>