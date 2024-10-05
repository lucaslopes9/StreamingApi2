<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$UserOnline = InfoUser(2);

$ContarUsuarioTotal = ContarUsuarioTotal($UserOnline);
$ContarUsuarioTotal[] = ContarTesteAtivo($UserOnline);
$string_array = implode("|", $ContarUsuarioTotal);

$_SESSION['InicioContarAtivo'] = $ContarUsuarioTotal[0];
$_SESSION['InicioContarEsgotado'] = $ContarUsuarioTotal[1];
$_SESSION['InicioContarBloqueado'] = $ContarUsuarioTotal[2];
$_SESSION['InicioContarTeste'] = $ContarUsuarioTotal[3];

echo $string_array;

}else{
	echo Redirecionar('login.php');
}
?>     
