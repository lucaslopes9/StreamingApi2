<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$_SESSION['obs'] = "";
	
}else{
	echo Redirecionar('login.php');
}	
?>