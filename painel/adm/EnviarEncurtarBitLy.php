<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$AcessoUser = InfoUser(3);
if( ($AcessoUser == 1) || ($AcessoUser == 2) ){
	
$LinkURLGerado = (isset($_POST['LinkURLGerado'])) ? $_POST['LinkURLGerado'] : '';
	
if(empty($LinkURLGerado)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
}
else{
	
$CadUser = InfoUser(2);
$SQL = "SELECT * FROM bit WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
$SQL->execute();
$Ln = $SQL->fetch();
$usuario = $Ln['usuario'];
$api = $Ln['api'];

$make_bitly_url = make_bitly_url($LinkURLGerado, $usuario, $api);
	
echo $make_bitly_url;
	
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>