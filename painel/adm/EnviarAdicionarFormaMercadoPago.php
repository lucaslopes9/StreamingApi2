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

	$ClientID = (isset($_POST['ClientID'])) ? $_POST['ClientID'] : '';
	$ClientSecret = (isset($_POST['ClientSecret'])) ? $_POST['ClientSecret'] : '';
	$CadUser = InfoUser(2);

	$SQL = "SELECT id, clientid, clientsecret FROM contamercadopago WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if(empty($ClientID)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['ClientIDeuco'], "danger");
	}
	elseif(empty($ClientSecret)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['ClientSecreteuco'], "danger");
	}
	elseif($Total > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['jeuca'], "danger");
	}
	else{
	
	$SQL = "INSERT INTO contamercadopago (
			CadUser,
            clientid,
            clientsecret
            ) VALUES (
            :CadUser,
            :clientid,
            :clientsecret
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_INT);
	$SQL->bindParam(':clientid', $ClientID, PDO::PARAM_INT);
	$SQL->bindParam(':clientsecret', $ClientSecret, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=mercadopago");
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