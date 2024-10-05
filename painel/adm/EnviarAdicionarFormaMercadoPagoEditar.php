<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoMercadoPago');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoMercadoPago = $VerificarAcesso[0];
 
if($PagamentoMercadoPago == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	$ClientID = (isset($_POST['ClientID'])) ? $_POST['ClientID'] : '';
	$ClientSecret = (isset($_POST['ClientSecret'])) ? $_POST['ClientSecret'] : '';
	$CadUser = InfoUser(2);
	
	if(empty($ClientID)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['ClientIDeuco'], "danger");
	}
	elseif(empty($ClientSecret)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['ClientSecreteuco'], "danger");
	}
	else{
		
	$SQL = "UPDATE contamercadopago SET
			clientid = :clientid,
			clientsecret = :clientsecret
			WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':clientid', $ClientID, PDO::PARAM_STR); 
	$SQL->bindParam(':clientsecret', $ClientSecret, PDO::PARAM_STR);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=mercadopago");
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