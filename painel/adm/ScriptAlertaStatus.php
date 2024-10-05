<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;

if(ProtegePag() == true){

$id = $_POST['id'];	
$perfil = $_POST['perfil'];	
$titulo = $_POST['titulo'];
$texto = $_POST['texto'];
$tipo = $_POST['tipo'];
$url = $_POST['url'];
$fa = $_POST['fa'];
$bt1 = $_TRA['sim'];
$bt2 = $_TRA['nao'];

echo MensagemConfirmarStatus($id, $perfil, $titulo, $texto, $tipo, $url, $fa, $bt1, $bt2);
            
}else{
	echo Redirecionar('login.php');
}
?>