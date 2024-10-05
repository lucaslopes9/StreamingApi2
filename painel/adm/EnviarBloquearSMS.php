<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('SMSadicionarBloquear');
$VerificarAcesso = VerificarAcesso('sms_adicionar', $ColunaAcesso);
$SMSadicionarBloquear = $VerificarAcesso[0];

if($SMSadicionarBloquear == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	
	$CadUser = InfoUser(2);
	$bloqueado = "S";
	$SQL = "UPDATE sms SET
			bloqueado = :bloqueado
            WHERE id = :id AND CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=sms-adicionar");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['bcs'], "success", "index.php?p=sms-adicionar");
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