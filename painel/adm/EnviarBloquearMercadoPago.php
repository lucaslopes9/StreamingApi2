<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('PagamentoMercadoPago');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAdmin);
$PagamentoMercadoPago = $VerificarAcesso[0];
 
if($PagamentoMercadoPago == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 	
	$CadUser = InfoUser(2);
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	
	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
		
	$bloqueado = "S";
	$SQL = "UPDATE contamercadopago SET
			bloqueado = :bloqueado
            WHERE id = :id AND CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['bcs'], "success", "index.php?p=mercadopago");
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