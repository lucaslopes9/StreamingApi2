<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoPagSeguro');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoPagSeguro = $VerificarAcesso[0];
 
if($PagamentoPagSeguro == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	$Email = (isset($_POST['Email'])) ? $_POST['Email'] : '';
	$Token = (isset($_POST['Token'])) ? $_POST['Token'] : '';
	$CadUser = InfoUser(2);
	
	if(empty($Email)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( substr_count($Email, "@") == 0 || substr_count($Email, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	elseif(empty($Token)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['tokeneuco'], "danger");
	}
	else{
		
	$SQL = "UPDATE contapagseguro SET
			email = :email,
			token = :token
			WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR); 
	$SQL->bindParam(':token', $Token, PDO::PARAM_STR);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=pagseguro");
	}
		
		
	}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>