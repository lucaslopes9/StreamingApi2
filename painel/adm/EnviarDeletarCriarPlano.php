<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAcesso = array('PagamentoPagSeguro', 'PagamentoPayPal', 'PagamentoMercadoPago', 'PagamentoContaBancaria');
	$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
	$PagamentoPagSeguro = $VerificarAcesso[0];
	$PagamentoPayPal = $VerificarAcesso[1];
	$PagamentoMercadoPago = $VerificarAcesso[2];
	$PagamentoContaBancaria = $VerificarAcesso[3];

	if( ($PagamentoPagSeguro == 'S') || ($PagamentoPayPal == 'S') || ($PagamentoMercadoPago == 'S') || ($PagamentoContaBancaria == 'S') ){ 

	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	$CadUser = InfoUser(2);
	
	$SQL = "DELETE FROM planos WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=criar-plano");
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