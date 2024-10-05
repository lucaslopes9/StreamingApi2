<?php
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){

Sair();
    
}else{
	echo Redirecionar('login.php');
}	
?>