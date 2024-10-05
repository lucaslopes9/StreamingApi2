<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('OpcoesCircular');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAdmin);
$OpcoesCircular = $VerificarAcesso[0];
 
if($OpcoesCircular == 'S'){
	
$id = isset($_POST['id']) ? $_POST['id'] : '';
$tipo = "Email";
$CadUser = InfoUser(2);
	
$SQL = "SELECT mensagem FROM email_modelo WHERE CadUser = :CadUser AND tipo = :tipo AND id = :id";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR);
$SQL->bindParam(':id', $id, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();

echo empty(trim($Ln['mensagem'])) ? "" : trim($Ln['mensagem']);


}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>